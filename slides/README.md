# Slides

Welcome to the slides! Here they are. Isn't that amazing?

## Readiness status

I'm still working on the slides. If the checkbox isn't checked, it means you shouldn't use them yet.

#### Part 1

- [x] Part 1: Session 1
- [x] Part 1: Session 2
- [x] Part 1: Session 3
- [x] Part 1: Session 4
- [x] Part 1: Session 5
- [x] Part 1: Session 6
- [ ] Part 1: Session 7
- [ ] Part 1: Session 8

#### Part 2

- [ ] Part 2: Session 1
- [ ] Part 2: Session 2
- [ ] Part 2: Session 3
- [ ] Part 2: Session 4
- [ ] Part 2: Session 5
- [ ] Part 2: Session 6
- [ ] Part 2: Session 7
- [ ] Part 2: Session 8
- [ ] Part 2: Session 9
- [ ] Part 2: Session 10
- [ ] Part 2: Session 11

## Compiling the slides

You'll need to first have [Tectonic](https://tectonic-typesetting.github.io/en-US/) installed. The good news is that this means that you don't need to install LaTeX!

## Notes

### Regarding handout mode
By default, these slides are presented in "handout mode", meaning they don't have transitions. If you want to compile them a slide deck with transitions (useful during teaching), remove the `handout` directive from the first line of the slide deck, and then run the corresponding `make` command.

### Converting from SVG
This is for my use only, please ignore:
`magick -density 4000 input.svg -resize 4000x output.png`
