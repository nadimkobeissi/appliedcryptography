# Slides

Welcome! This folder contains presentation slides and instructions for compiling them.

## Compiling the slides

You'll need to first have [Tectonic](https://tectonic-typesetting.github.io/en-US/) and [qpdf](https://qpdf.sourceforge.io/) installed. The good news is that this means that you don't need to install LaTeX!

## Notes

### Regarding handout mode
By default, these slides are presented in "handout mode", meaning they don't have transitions. If you want to compile them a slide deck with transitions (useful during teaching), remove the `handout` directive from the first line of the slide deck, and then run the corresponding `make` command.

### Converting from SVG
This is for my use only, please ignore:
`magick -density 4000 input.svg -resize 4000x output.png`
