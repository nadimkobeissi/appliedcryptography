# Slides

## Compiling the slides

Use the Makefile:

- `make <part>-<session>`: compile a single slide deck with the output in `pdf/`. Example: `make 1-3`.
- `make clean`: remove intermediate files created during compilation.
- `make all`: make every slide deck, place output in `pdf/`.

## Notes

### Regarding handout mode
By default, these slides are presented in "handout mode", meaning they don't have transitions. If you want to compile them a slide deck with transitions (useful during teaching), remove the `handout` directive from the first line of the slide deck, and then run the corresponding `make` command.

### Regarding Inkscape
If you decide to compile the slides locally, you will need to have [Inkscape](https://inkscape.org) installed and available via the command line. This is because LaTeX has no native support for SVG images, and we use a package that calls Inkscape to do compile-time image format conversion.

On macOS: `brew install --cask inkscape`
On Linux: God help you, figure it out based on your Linux distribution.
