const updatedInit = () => {
	const lastUpdatedElement = document.getElementById("lastUpdated");
	const updatedLink = document.createElement("a");
	updatedLink.href =
		"https://git.appliedcryptography.page/nadim/appliedcryptography/commits/branch/main";
	fetch(
		"https://git.appliedcryptography.page/api/v1/repos/nadim/appliedcryptography/commits?limit=1&sha=main",
	)
		.then((response) => response.json())
		.then((data) => {
			if (Array.isArray(data) && data.length > 0) {
				const latestCommitDate = new Date(data[0].commit.author.date);
				const options = {
					year: "numeric",
					month: "long",
					day: "numeric",
					hour: "numeric",
					minute: "numeric",
					hour12: true,
				};
				const formattedDate = latestCommitDate.toLocaleString(
					undefined,
					options,
				);
				updatedLink.innerText = formattedDate;
				lastUpdatedElement.innerHTML = "";
				lastUpdatedElement.appendChild(updatedLink);
				const period = document.createElement("span");
				period.innerText = ".";
				lastUpdatedElement.appendChild(period);
			}
		})
		.catch((error) => {
			console.error("Error fetching commit data:", error);
			updatedLink.innerText = "View history";
			lastUpdatedElement.innerHTML = "";
			lastUpdatedElement.appendChild(updatedLink);
		});
};
