const dateInit = () => {
	const footerYear = document.getElementById(`footerYear`);
	footerYear.innerText = new Date().getFullYear();
};