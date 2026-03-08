/* Arkana Dashboard — Login auto-submit */
(function() {
    var params = new URLSearchParams(window.location.search);
    var token = params.get('token');
    if (token) {
        var field = document.getElementById('token');
        var form = document.querySelector('.login-form');
        if (field && form) {
            field.value = token;
            form.submit();
        }
    }
})();
