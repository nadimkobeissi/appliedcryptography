export const menuInit = () => {
	const mobileMenuToggle = document.querySelector(".mobile-menu-toggle")
	const navbarLinks = document.querySelector(".navbar-links")

	const setOpen = (open) => {
		mobileMenuToggle.classList.toggle("active", open)
		navbarLinks.classList.toggle("active", open)
		document.body.classList.toggle("menu-open", open)
		mobileMenuToggle.setAttribute("aria-expanded", open ? "true" : "false")
	}

	mobileMenuToggle.setAttribute("aria-controls", "navbar-links")
	mobileMenuToggle.setAttribute("aria-expanded", "false")
	navbarLinks.id = navbarLinks.id || "navbar-links"

	mobileMenuToggle.addEventListener("click", () => {
		setOpen(!mobileMenuToggle.classList.contains("active"))
	})

	const navLinks = document.querySelectorAll(".navbar-links a")
	navLinks.forEach((link) => {
		link.addEventListener("click", () => setOpen(false))
	})

	// Close when viewport widens past the mobile breakpoint.
	const mq = window.matchMedia("(min-width: 901px)")
	mq.addEventListener("change", (e) => {
		if (e.matches) setOpen(false)
	})

	// Close on Escape.
	document.addEventListener("keydown", (e) => {
		if (e.key === "Escape" && mobileMenuToggle.classList.contains("active")) setOpen(false)
	})
}