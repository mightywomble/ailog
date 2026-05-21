document.addEventListener('DOMContentLoaded', () => {
    // Load header, sidebar, and main components
    loadComponent('#header-component', '/templates/components/header.html');
    loadComponent('#sidebar-component', '/templates/components/sidebar.html');
    loadComponent('#main-component', '/templates/components/main.html');

    // Utility function to load HTML components
    async function loadComponent(selector, url) {
        try {
            const response = await fetch(url);
            const content = await response.text();
            document.querySelector(selector).innerHTML = content;
        } catch (error) {
            console.error('Error loading component:', error);
        }
    }
});

