export const countdownInit = () => {
	const targetDate = new Date("2025-08-26T12:30:00+03:00") // Beirut time (UTC+3)
	const countdownElement = document.getElementById("countdown")
	let countdownInterval = 0

	const updateCountdown = () => {
		const now = new Date()
		const difference = targetDate - now
		if (difference > 0) {
			const days = Math.floor(difference / (1000 * 60 * 60 * 24))
			const hours = Math.floor((difference % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))
			const minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60))
			const seconds = Math.floor((difference % (1000 * 60)) / 1000)
			countdownElement.textContent = `${days} days, ${hours} hours, ${minutes} minutes and ${seconds} seconds.`
		} else {
			const container = document.getElementById("countdown-container")
			if (container) {
				container.remove()
				clearInterval(countdownInterval)
			}
		}
	}

	updateCountdown()
	countdownInterval = setInterval(updateCountdown, 1000)
}
