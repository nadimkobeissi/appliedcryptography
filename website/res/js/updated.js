const updatedInit = () => {
	const repoUri = "https://cedarcrypt.org/nadim/appliedcryptography/commits/branch/main"
	const apiUri = "https://cedarcrypt.org/api/v1/repos/nadim/appliedcryptography/commits?limit=1&sha=main"
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
						const lastUpdatedElement = document.getElementById("lastUpdated")
						const updatedLink = document.createElement("a")
						updatedLink.href = repoUri
						updatedLink.innerText = formattedDate
						lastUpdatedElement.innerHTML = ""
						lastUpdatedElement.appendChild(updatedLink)
						const period = document.createElement("span")
						period.innerText = "."
						lastUpdatedElement.appendChild(period)
					} else {
						updatedError("Invalid date")
					}
				} else {
					updatedError("Invalid date")
				}
			}
		})
		.catch(updatedError)
}

const updatedError = (error) => {
	const lastUpdatedElement = document.getElementById("lastUpdated")
	const updatedLink = document.createElement("a")
	updatedLink.href = repoUri
	console.error("Error fetching commit data:", error)
	updatedLink.innerText = "View history"
	lastUpdatedElement.innerHTML = ""
	lastUpdatedElement.appendChild(updatedLink)
}
