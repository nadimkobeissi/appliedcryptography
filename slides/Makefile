all:
	@make 1-1
	@make 1-2

clean:
	@latexmk -C;
	@rm -rf svg-inkscape

1-1:
	@make clean
	@latexmk -shell-escape "1-1"
	@mv "1-1.pdf" pdf/.
	@make clean

1-2:
	@make clean
	@latexmk -shell-escape "1-2.tex"
	@mv "1-2.pdf" pdf/.
	@make clean
