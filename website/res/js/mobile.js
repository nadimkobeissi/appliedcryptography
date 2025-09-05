export const mobileInit = () => {
	const mobileElements = document.getElementsByClassName("mobile-only")
	const desktopElements = document.getElementsByClassName("desktop-only")
	if (isMobileDevice()) {
		for (let element of mobileElements) {
			element.style.display = "block"
		}
		for (let element of desktopElements) {
			element.style.display = "none"
		}
	} else {
		for (let element of mobileElements) {
			element.style.display = "none"
		}
		for (let element of desktopElements) {
			element.style.display = "block"
		}
	}
}

const isMobileDevice = () => {
	return /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i.test(navigator.userAgent.toLowerCase())
}
