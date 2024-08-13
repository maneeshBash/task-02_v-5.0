document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'login.html'; // Redirect to login page if no token found...
    }
});

function logout(){
    localStorage.removeItem('token');
    window.location.href = 'login.html';
}
