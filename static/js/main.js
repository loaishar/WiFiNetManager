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
                    // Confirm token is set before redirecting
                    if (localStorage.getItem('access_token')) {
                        window.location.href = '/devices';
                    } else {
                        throw new Error('Failed to store access token');
                    }
                } else {
                    throw new Error(data.message || 'Login failed');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert(error.message || 'An error occurred during login. Please try again.');
            });
        });
    }

    function getAuthHeader() {
        const token = localStorage.getItem('access_token');
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    }

    function handleUnauthorized() {
        localStorage.removeItem('access_token');
        window.location.href = '/login';
    }

    if (deviceList) {
        function loadDevices() {
            fetch('/api/devices', {
                headers: getAuthHeader()
            })
            .then(response => {
                if (response.status === 401) {
                    handleUnauthorized();
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
            fetch(`/api/devices/${deviceId}/toggle`, {
                method: 'POST',
                headers: getAuthHeader()
            })
            .then(response => {
                if (response.status === 401) {
                    handleUnauthorized();
                    return;
                }
                return response.json();
            })
            .then(data => {
                if (data && data.success) {
                    loadDevices();
                } else {
                    throw new Error('Failed to toggle device status');
                }
            })
            .catch(error => {
                console.error('Error toggling device:', error);
                alert(error.message || 'An error occurred. Please try again.');
            });
        };

        if (scanButton) {
            scanButton.addEventListener('click', function() {
                fetch('/api/scan', {
                    method: 'POST',
                    headers: getAuthHeader()
                })
                .then(response => {
                    if (response.status === 401) {
                        handleUnauthorized();
                        return;
                    }
                    return response.json();
                })
                .then(data => {
                    if (data && data.success) {
                        loadDevices();
                    } else {
                        throw new Error('Failed to scan for new devices');
                    }
                })
                .catch(error => {
                    console.error('Error scanning devices:', error);
                    alert(error.message || 'An error occurred while scanning. Please try again.');
                });
            });
        }
    }
});
