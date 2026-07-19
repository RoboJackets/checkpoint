const app = Elm.Main.init(
    {
        flags: Object.assign({}, window.serverData, {
            theme: document.documentElement.getAttribute("data-bs-theme") || "light",
        }),
    }
);

app.ports.setTheme.subscribe(function (theme) {
    localStorage.setItem("theme", theme);
    document.documentElement.setAttribute("data-bs-theme", theme);
});
