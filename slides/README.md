# Slides

Welcome! This folder contains presentation slides and instructions for compiling them.

## Notes

### Regarding handout mode
By default, these slides are presented in "handout mode", meaning they don't have transitions. If you want to compile them a slide deck with transitions (useful during teaching), remove the `handout` directive from the first line of the slide deck, and then run the corresponding `make` command.

### Converting from SVG
This is for my use only, please ignore:
`magick -density 4000 input.svg -resize 4000x output.png`
