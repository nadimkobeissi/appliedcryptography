const updatedInit = () => {
	fetch(
		"https://api.github.com/repos/nadimkobeissi/appliedcryptography/commits?per_page=1&sha=main",
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
				document.getElementById("lastUpdated").innerText =
					formattedDate + ".";
			}
		})
		.catch((error) => console.error("Error fetching commit data:", error));
};
