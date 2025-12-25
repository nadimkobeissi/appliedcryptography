export const menuInit = () => {
	const mobileMenuToggle = document.querySelector(".mobile-menu-toggle")
	const navbarLinks = document.querySelector(".navbar-links")

	mobileMenuToggle.addEventListener("click", () => {
		mobileMenuToggle.classList.toggle("active")
		navbarLinks.classList.toggle("active")
	})

	const navLinks = document.querySelectorAll(".navbar-links a")
	navLinks.forEach((link) => {
		link.addEventListener("click", () => {
			mobileMenuToggle.classList.remove("active")
			navbarLinks.classList.remove("active")
		})
	})
}