setCookie = (cName, cValue, expDays) => {
    let date = new Date();
    date.setTime(date.getTime() + (expDays * 24 * 60 * 60 * 1000));
    const expires = "expires=" + date.toUTCString();
    document.cookie = cName + "=" + cValue + "; " + expires + "; path=/";
}

getCookie = (cName) => {
    const name = cName + "=";
    const cDecoded = decodeURIComponent(document.cookie);
    const cArr = cDecoded.split("; ");
    let value;
    cArr.forEach(val => {
        if (val.indexOf(name) === 0) value = val.substring(name.length);
    })
    return value;
}

document.querySelector("#btn_cookies").addEventListener("click", () => {
    document.querySelector("#cookies").style.display = "none";
    setCookie("cookie", "accepted", 30);
})

document.querySelector("#btn_cookies_delete").addEventListener("click", () => {
    document.querySelector("#cookies").style.display = "none";
    setCookie("cookie", "denied", 30);
})

cookieMessage = () => {
    const cookieStatus = getCookie("cookie");
    if (!cookieStatus) {
        document.querySelector("#cookies").style.display = "block";
    }
}

window.addEventListener("load", cookieMessage);
