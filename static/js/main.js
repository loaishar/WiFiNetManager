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
                    // Redirect to devices page after setting the token
                    window.location.href = '/devices';
                } else {
                    alert('Login failed. Please try again.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred during login. Please try again.');
            });
        });
    }

    if (deviceList) {
        function loadDevices() {
            const token = localStorage.getItem('access_token');
            if (!token) {
                window.location.href = '/login';
                return;
            }

            fetch('/api/devices', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
            .then(response => {
                if (response.status === 401) {
                    // Token is invalid or expired
                    localStorage.removeItem('access_token');
                    window.location.href = '/login';
                    return;
                }
                return response.json();
            })
            .then(devices => {
                if (devices) {
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
                }
            })
            .catch(error => {
                console.error('Error fetching devices:', error);
                alert('Failed to load devices. Please try again.');
            });
        }

        loadDevices();

        window.toggleDevice = function(deviceId) {
            const token = localStorage.getItem('access_token');
            if (!token) {
                window.location.href = '/login';
                return;
            }

            fetch(`/api/devices/${deviceId}/toggle`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            })
            .then(response => {
                if (response.status === 401) {
                    localStorage.removeItem('access_token');
                    window.location.href = '/login';
                    return;
                }
                return response.json();
            })
            .then(data => {
                if (data && data.success) {
                    loadDevices();
                } else {
                    alert('Failed to toggle device status. Please try again.');
                }
            })
            .catch(error => {
                console.error('Error toggling device:', error);
                alert('An error occurred. Please try again.');
            });
        };

        if (scanButton) {
            scanButton.addEventListener('click', function() {
                const token = localStorage.getItem('access_token');
                if (!token) {
                    window.location.href = '/login';
                    return;
                }

                fetch('/api/scan', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
                .then(response => {
                    if (response.status === 401) {
                        localStorage.removeItem('access_token');
                        window.location.href = '/login';
                        return;
                    }
                    return response.json();
                })
                .then(data => {
                    if (data && data.success) {
                        loadDevices();
                    } else {
                        alert('Failed to scan for new devices. Please try again.');
                    }
                })
                .catch(error => {
                    console.error('Error scanning devices:', error);
                    alert('An error occurred while scanning. Please try again.');
                });
            });
        }
    }
});
