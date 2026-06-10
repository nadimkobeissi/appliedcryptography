export const revealInit = () => {
	const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches
	if (reduced || !("IntersectionObserver" in window)) {
		return
	}

	const targets = document.querySelectorAll(".card, .topic, .section-header, .alert, .week-grid .card, .cal-ribbon")
	const viewportHeight = window.innerHeight

	const observer = new IntersectionObserver((entries) => {
		let batchIndex = 0
		entries.forEach((entry) => {
			if (entry.isIntersecting) {
				entry.target.style.transitionDelay = `${Math.min(batchIndex, 5) * 45}ms`
				entry.target.classList.add("revealed")
				observer.unobserve(entry.target)
				batchIndex++
			}
		})
	}, { rootMargin: "0px 0px -7% 0px", threshold: 0.04 })

	targets.forEach((el) => {
		// Only pre-hide elements that start below the fold, so nothing
		// visible ever flashes and content stays intact without JS.
		if (el.getBoundingClientRect().top > viewportHeight * 0.92) {
			el.classList.add("reveal")
			observer.observe(el)
		}
	})
}
