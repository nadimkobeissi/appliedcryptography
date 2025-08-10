const updatedInit = () => {
	const lastUpdatedElement = document.getElementById("lastUpdated")
	const updatedLink = document.createElement("a")
	const repoUri = "https://cedarcrypt.org/nadim/appliedcryptography/commits/branch/main"
	const apiUri = "https://cedarcrypt.org/api/v1/repos/nadim/appliedcryptography/commits?limit=1&sha=main"
	updatedLink.href = repoUri
	fetch(apiUri)
		.then((response) => response.json())
		.then((data) => {
			if (Array.isArray(data) && data.length > 0) {
				if (data[0]?.commit?.author?.date) {
					const latestCommitDate = new Date(data[0].commit.author.date)
					if (!isNaN(latestCommitDate.getTime())) {
						const formattedDate = latestCommitDate.toLocaleString(undefined, {
							year: "numeric",
							month: "long",
							day: "numeric",
							hour: "numeric",
							minute: "numeric",
							hour12: true,
						})
						updatedLink.innerText = formattedDate
						lastUpdatedElement.innerHTML = ""
						lastUpdatedElement.appendChild(updatedLink)
						const period = document.createElement("span")
						period.innerText = "."
						lastUpdatedElement.appendChild(period)
					}
				}
			}
		})
		.catch((error) => {
			console.error("Error fetching commit data:", error)
			updatedLink.innerText = "View history"
			lastUpdatedElement.innerHTML = ""
			lastUpdatedElement.appendChild(updatedLink)
		})
}
