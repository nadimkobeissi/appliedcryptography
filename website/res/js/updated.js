const REPO_URI = "https://git.cedarcrypt.org/nadim/appliedcryptography/commits/branch/main"
const API_URI = "https://git.cedarcrypt.org/api/v1/repos/nadim/appliedcryptography/commits?limit=1&sha=main"

const showLink = (text) => {
	const link = document.createElement("a")
	link.href = REPO_URI
	link.innerText = text
	const host = document.getElementById("lastUpdated")
	host.innerHTML = ""
	host.appendChild(link)
}

export const updatedInit = () => {
	fetch(API_URI)
		.then((response) => response.json())
		.then((data) => {
			const date = new Date(data?.[0]?.commit?.author?.date)
			if (isNaN(date.getTime())) throw new Error("Invalid date")
			showLink(date.toLocaleString(undefined, {
				year: "numeric",
				month: "long",
				day: "numeric",
				hour: "numeric",
				minute: "numeric",
				hour12: true,
			}))
			document.getElementById("lastUpdated").appendChild(document.createTextNode("."))
		})
		.catch((error) => {
			console.error("Error fetching commit data:", error)
			showLink("View history")
		})
}
