function copyTextToClipboard(text) {
    var textArea = document.createElement("textarea");
  
    //
    // *** This styling is an extra step which is likely not required. ***
    //
    // Why is it here? To ensure:
    // 1. the element is able to have focus and selection.
    // 2. if element was to flash render it has minimal visual impact.
    // 3. less flakyness with selection and copying which **might** occur if
    //    the textarea element is not visible.
    //
    // The likelihood is the element won't even render, not even a flash,
    // so some of these are just precautions. However in IE the element
    // is visible whilst the popup box asking the user for permission for
    // the web page to copy to the clipboard.
    //
  
    // Place in top-left corner of screen regardless of scroll position.
    textArea.style.position = 'fixed';
    textArea.style.top = 0;
    textArea.style.left = 0;
  
    // Ensure it has a small width and height. Setting to 1px / 1em
    // doesn't work as this gives a negative w/h on some browsers.
    textArea.style.width = '2em';
    textArea.style.height = '2em';
  
    // We don't need padding, reducing the size if it does flash render.
    textArea.style.padding = 0;
  
    // Clean up any borders.
    textArea.style.border = 'none';
    textArea.style.outline = 'none';
    textArea.style.boxShadow = 'none';
  
    // Avoid flash of white box if rendered for any reason.
    textArea.style.background = 'transparent';
  
    textArea.value = text;
  
    document.body.appendChild(textArea);
  
    textArea.select();
  
    try {
      var successful = document.execCommand('copy');
    } catch (err) {
      console.log('Oops, unable to copy');
    }
  
    document.body.removeChild(textArea);
}


// Sidebar toggle
const sidebarToggle = document.body.querySelector('#sidebar-toggle');
sidebarToggle.addEventListener('click', function() {
    document.querySelector("#sidebar").classList.toggle('collapsed');
});

$(window).on('load', function() {
    if($(window).width() < 768) {
        $('#sidebar').addClass('collapsed');
    }
    if($(window).width() >= 768) {
        $('#sidebar').removeClass('collapsed');
    }
})


document.addEventListener("DOMContentLoaded", function () {
    // API-Endpunkt für aktive Benutzer
    const activeUsersUrl = "/monitoring/get-active-users/";

    // HTML-Elemente
    const badgeElement = document.getElementById("activeUsersBadge");
    const dropdownMenu = document.createElement("div");
    dropdownMenu.classList.add("dropdown-menu", "dropdown-menu-end");
    badgeElement.after(dropdownMenu);

    // Funktion zum Abrufen der aktiven Benutzer
    async function fetchActiveUsers() {
        try {
            const response = await fetch(activeUsersUrl);
            if (!response.ok) throw new Error("Fehler beim Laden der aktiven Benutzer");

            const data = await response.json();

            // Anzahl der aktiven Benutzer aktualisieren
            const activeUserCount = data.active_users.length;
            const countSpan = badgeElement.querySelector(".active-admins-count");
            if (countSpan) {
                countSpan.textContent = activeUserCount;
            }

            // Dropdown-Inhalt neu setzen
            dropdownMenu.innerHTML = "";
            if (activeUserCount === 0) {
                dropdownMenu.innerHTML = '<span class="dropdown-item">Keine aktiven Benutzer</span>';
            } else {
                data.active_users.forEach(user => {
                    const userItem = document.createElement("span");
                    userItem.classList.add("dropdown-item");
                    userItem.textContent = `${user.first_name} ${user.last_name} (${user.username})`;
                    dropdownMenu.appendChild(userItem);
                });
            }
        } catch (error) {
            console.error("Fehler beim Abrufen der aktiven Benutzer:", error);
        }
    }

    // Initiale Abfrage beim Laden der Seite
    fetchActiveUsers();

    // Alle 10 Sekunden aktualisieren
    setInterval(fetchActiveUsers, 10000);
});