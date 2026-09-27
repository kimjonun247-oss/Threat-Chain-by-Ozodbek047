const params = new URLSearchParams(location.search);
document.getElementById('out').innerHTML = params.get('q');
