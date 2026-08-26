export const navspyInit = () => {
	const navbar = document.querySelector(".navbar")
	if (!navbar) {
		return
	}

	const links = [...document.querySelectorAll(".navbar-links a[href^='#']")].filter((a) => a.hash.length > 1)
	const sections = links
		.map((a) => document.getElementById(a.hash.slice(1)))
		.filter(Boolean)

	const toTop = document.createElement("button")
	toTop.type = "button"
	toTop.className = "to-top"
	toTop.setAttribute("aria-label", "Back to top")
	toTop.innerHTML = `<i class="icon ph-duotone ph-arrow-up" aria-hidden="true"></i>`
	toTop.addEventListener("click", () => {
		window.scrollTo({
			top: 0
		})
	})
	document.body.appendChild(toTop)

	let ticking = false
	const update = () => {
		ticking = false
		navbar.classList.toggle("scrolled", window.scrollY > 8)
		toTop.classList.toggle("visible", window.scrollY > 640)

		let currentId = null
		const probe = window.scrollY + 120
		sections.forEach((section) => {
			if (section.getBoundingClientRect().top + window.scrollY <= probe) {
				currentId = section.id
			}
		})
		links.forEach((a) => {
			a.classList.toggle("active", a.hash === `#${currentId}`)
		})
	}

	document.addEventListener("scroll", () => {
		if (!ticking) {
			ticking = true
			requestAnimationFrame(update)
		}
	}, {
		passive: true
	})

	update()
}