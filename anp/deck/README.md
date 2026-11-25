# The slide deck

"Cold-Stock Rescue: Agents Across Companies": 26 slides with speaker notes that tell the demo's story (the night, the agent, Couchbase and the fleet, the
architecture and the choices behind it, the checks). It is the deck to use with [`../DEMO.md`](../DEMO.md), the guide to building and showing the demo live.

## What this folder is

The deck was made as a **Slides artifact** in Claude, in the Couchbase 2026 design system, and these are its source files, exactly as the artifact holds them:

```text
project/deck.json         the index: title, slide order, sections, fonts, the design system it was built on
project/deck.css          the shared styles (colours, type, cards, the architecture diagram's boxes and numbered links)
project/slides/<id>.html  one file per slide; the speaker notes are in each file's <aside>
images/                   the two screenshots the deck uses (the control room, the head office's fleet view), taken from the demo's recording
preview.ps1               builds a local preview page from the sources (below)
```

Slide order, from `deck.json`: cover, the night, the clock, the control room, strangers, asking, rules, authority, deals, *Couchbase* (divider, four pieces, fleet view,
approvals and tokens), *architecture* (divider, six layers, the diagram, the legend, identity, messaging, commitments, data, the fleet, the brain, the choices table),
the checks, and the closing.

## Look at it without Claude

```powershell
pwsh anp/deck/preview.ps1            # writes anp/deck/preview.html: every slide, stacked at 1920x1080
pwsh anp/deck/preview.ps1 -Shots     # also one PNG per slide in anp/deck/shots (needs Microsoft Edge)
```

This is an approximation: the browser stands in for the real viewer, so the brand fonts (Centra No2, Inter) are replaced by a system font, the Couchbase logo and the
arrows between boxes do not draw, and the speaker notes are hidden. Line breaks can differ a little. Use it to read the content and check a layout, not to present from.

## Present from it, or change it

- **To present:** open the deck in Claude's Slides viewer, if you have it published, and present or export from there. A copy of the source in this folder is not a
  presentable deck by itself, because the viewer supplies the fonts, the logo and the arrows.
- **To change it:** ask Claude, with its Artifact tool, to publish this folder as a Slides artifact (`root` = this folder, so `project/deck.json` is the index), or to
  update the existing artifact from it. Two things in the sources only mean something there:
  - `/_blob/<id>` in two `<img>` tags (slides `control-room` and `fleet-view`) points at an image stored in the artifact. The same pictures are in `images/`; upload them again
    and put the new addresses in.
  - `project/ds/couchbase-2026/...` (the fonts, the tokens and the logo) is installed from the Couchbase 2026 Design System when the deck is published, and is not in this
    folder. `deck.json` records which design system and version it came from.
- **To update the screenshots:** record the demo (`cargo xtask cold-rescue --gateway --record demo.mp4`), take a frame of the control room mid-rescue and of the fleet view at the
  end, and replace the two files in `images/`.

## Things to know

- The numbers in the deck (44, 18, 20, 21 and 19 checks; 60 groups of unit tests; €10,500 in six deals) are the ones the checks printed when the deck was made; if you change the
  demo, run the checks again and update slide 25 ("Every Claim Has A Test") and the closing.
- Slide 16's diagram is positioned by hand (every box and link has coordinates in `arch-diagram.html`, with a comment listing the boxes); change a box's size and its
  links need new coordinates.
- The store, the companies and their prices in the story are fictional; the protocol, the signatures and the encryption are real. The deck says so on the cover and the closing slide.
