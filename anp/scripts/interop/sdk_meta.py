"""ANP-06 with the official SDK's MetaProtocol, in both roles, over this project's HTTP binding of the message stream.

  sdk_meta.py requester BASE     the SDK asks a running node (POST BASE/anp/meta) for a protocol
  sdk_meta.py provider PORT      the SDK answers: a small server for this project's `anp-meta ask`

The SDK negotiates with a language model; none is run here. A stand-in answers the two LLM calls the negotiator makes with a fixed
policy ("a2a-json-rpc" and "json-rpc-lite" are protocols this side has), so the SDK's own state machine, framing, round numbers
and codeGeneration messages are what is exercised. `openai` is not installed and is stubbed out (nothing calls it).
"""
import asyncio, json, os, struct, sys, types, urllib.request, urllib.error
from unittest import mock
sys.path.insert(0, os.environ.get("ANP_SDK_LIBS", os.path.expanduser("~/anp-interop/libs")))
sys.modules["openai"] = mock.MagicMock()
from anp.meta_protocol.meta_protocol import MetaProtocol

KNOWN = ("a2a-json-rpc", "json-rpc-lite")
OWN_TEXT = "json-rpc-lite: one JSON object per message, {id, method, params} and {id, result|error}."

def between(text, marker):
    start = text.index(f"--[ {marker} ]--\n") + len(f"--[ {marker} ]--\n")
    return text[start:text.index("\n--[END]--", start)]

class FakeLLM:
    """What a model would be asked: write a first proposal, and judge the other side's."""
    model_name = "stand-in"
    def __init__(self, first=None):
        self.first = first or "a2a-json-rpc: JSON-RPC 2.0 over HTTP, methods SendMessage, GetTask, ListTasks, CancelTask."
        self.calls = []
        async def create(model, messages, **kw):
            theirs = between(messages[1]["content"], "counterparty_latest_protocol")
            self.calls.append(theirs)
            if any(k in theirs for k in KNOWN):
                body = {"status": "accepted"}
            else:
                body = {"status": "negotiating", "candidate_protocol": OWN_TEXT, "modification_summary": "this side implements json-rpc-lite"}
            msg = types.SimpleNamespace(content=json.dumps(body), tool_calls=None)
            return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])
        self.client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=types.SimpleNamespace(create=create)))
    async def async_generate_response(self, system_prompt, user_prompt):
        return self.first

def split_frames(body):
    out = []
    while body:
        n = struct.unpack(">I", body[:4])[0]
        out.append(body[4:4 + n])
        body = body[4 + n:]
    return out

mode = sys.argv[1]
ok = True
def check(name, cond, detail=""):
    global ok
    ok &= bool(cond)
    print(("PASS  " if cond else "FAIL  ") + name + ("" if cond else "  " + str(detail)[:300]))

if mode == "requester":
    BASE = sys.argv[2].rstrip("/")
    async def run(first, label):
        sent, got_state = [], {}
        mp = None
        loop = asyncio.get_running_loop()
        def post(data):
            req = urllib.request.Request(BASE + "/anp/meta", data=data, method="POST", headers={"x-anp-session": "sdk-" + label.replace(" ", "-") + "-00001", "Content-Type": "application/octet-stream"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read(), r.headers.get("x-anp-meta-state")
        async def send(data):
            sent.append(data)
            body, state = await loop.run_in_executor(None, post, data)
            got_state["state"] = state
            for f in split_frames(body):
                mp.handle_meta_data(f)
        llm = FakeLLM(first)
        mp = MetaProtocol(send_callback=send, llm=llm)
        await mp.negotiate_protocol("tasks for an agent", "a message", "a task")   # (False, "") is returned when no code is generated: that is the SDK's design
        generated = await mp.wait_for_code_generation()
        return mp, sent, got_state, generated, llm
    async def main():
        mp, sent, st, generated, llm = await run(None, "named")
        first = json.loads(sent[0][1:])
        check("the SDK's first message is a protocolNegotiation, round 1, status negotiating, behind a meta header byte (0x00)", sent[0][0] == 0 and first["action"] == "protocolNegotiation" and first["sequenceId"] == 1 and first["status"] == "negotiating", first)
        check("the node accepted: its answer was `accepted` and the SDK finished negotiating", st.get("state") == "agreed:a2a-json-rpc", st)
        check("the node then said its code was ready (codeGeneration generated), which the SDK received", generated)
        check("the SDK answered the node's acceptance with its own (the trailing message the node must tolerate)", any(json.loads(s[1:]).get("status") == "accepted" for s in sent[1:]), [s[1:] for s in sent])
        mp2, sent2, st2, gen2, llm2 = await run("a protocol for ordering pizza: orders as XML.", "counter")
        check("a proposal the node does not have is answered with a counter-proposal (negotiating, round 2)", any(json.loads(s[1:]).get("sequenceId") == 3 for s in sent2) or st2.get("state") in ("agreed:a2a-json-rpc", "negotiating"), (st2, [s[1:] for s in sent2]))
        check("the SDK judged the node's counter and accepted it (it names a2a-json-rpc, which the stand-in knows): the negotiation ends agreed", st2.get("state") == "agreed:a2a-json-rpc", st2)
        check("the counter the SDK evaluated mentions the node's protocol", llm2.calls and "a2a-json-rpc" in llm2.calls[0], llm2.calls)
    asyncio.run(main())
    sys.exit(0 if ok else 1)

if mode == "provider":
    from aiohttp import web
    port = int(sys.argv[2])
    sessions = {}
    async def handler(request):
        sid = request.headers.get("x-anp-session", "")
        data = await request.read()
        if sid not in sessions:
            out = asyncio.Queue()
            async def send(d):
                await out.put(d)
            mp = MetaProtocol(send_callback=send, llm=FakeLLM())
            async def serve():
                await mp.wait_remote_negotiation()
                await mp.notify_code_generation()   # the generated code is the SDK's side being ready
            sessions[sid] = (mp, out, asyncio.create_task(serve()))
            await asyncio.sleep(0)
        mp, out, task = sessions[sid]
        mp.handle_meta_data(data)
        frames = []
        try:
            frames.append(await asyncio.wait_for(out.get(), 3))
            while True:
                frames.append(await asyncio.wait_for(out.get(), 0.4))
        except asyncio.TimeoutError:
            pass
        body = b"".join(struct.pack(">I", len(f)) + f for f in frames)
        return web.Response(body=body, headers={"x-anp-meta-state": "sdk", "Content-Type": "application/octet-stream"})
    app = web.Application()
    app.router.add_post("/anp/meta", handler)
    print("the SDK's MetaProtocol is serving on", port, flush=True)
    web.run_app(app, port=port, print=None)