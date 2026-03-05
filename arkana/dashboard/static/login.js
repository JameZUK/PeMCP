/* Arkana Dashboard — Login auto-submit */
(function() {
    var params = new URLSearchParams(window.location.search);
    var token = params.get('token');
    if (token) {
        document.getElementById('token').value = token;
        document.querySelector('.login-form').submit();
    }
})();
