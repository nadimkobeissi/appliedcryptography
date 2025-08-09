const collapsibleInit = () => {
	document.querySelectorAll(".collapsible-header").forEach((header) => {
		header.addEventListener("click", () => {
			header.classList.toggle("active")
			header.nextElementSibling.classList.toggle("active")
		})
	})
}
