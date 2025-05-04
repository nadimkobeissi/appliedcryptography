const collapsibleInit = () => {
	const collapsibleHeaders = document.querySelectorAll(".collapsible-header");
	collapsibleHeaders.forEach((header) => {
		header.addEventListener("click", () => {
			header.classList.toggle("active");
			const content = header.nextElementSibling;
			if (header.classList.contains("active")) {
				content.style.maxHeight = content.scrollHeight + "px";
			} else {
				content.style.maxHeight = "0px";
			}
		});
	});
};