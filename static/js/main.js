document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');

    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    'username': username,
                    'password': password
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.access_token) {
                    localStorage.setItem('access_token', data.access_token);
                    window.location.href = '/devices';
                }
            });
        });
    }

    if (deviceList) {
        function loadDevices() {
            fetch('/api/devices', {
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('access_token')
                }
            })
            .then(response => response.json())
            .then(devices => {
                deviceList.innerHTML = '';
                devices.forEach(device => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td>${device.name}</td>
                        <td>${device.ip_address}</td>
                        <td>${device.mac_address}</td>
                        <td>${device.status ? 'Online' : 'Offline'}</td>
                        <td>
                            <button class="btn btn-sm ${device.blocked ? 'btn-danger' : 'btn-success'}" onclick="toggleDevice(${device.id})">
                                ${device.blocked ? 'Unblock' : 'Block'}
                            </button>
                        </td>
                    `;
                    deviceList.appendChild(row);
                });
            });
        }

        loadDevices();

        window.toggleDevice = function(deviceId) {
            fetch(`/api/devices/${deviceId}/toggle`, {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + localStorage.getItem('access_token')
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadDevices();
                }
            });
        };

        if (scanButton) {
            scanButton.addEventListener('click', function() {
                fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Authorization': 'Bearer ' + localStorage.getItem('access_token')
                    }
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        loadDevices();
                    }
                });
            });
        }
    }
});
