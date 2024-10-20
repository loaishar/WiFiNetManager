document.addEventListener('DOMContentLoaded', function() {
    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');

    console.log('DOM Content Loaded');

    function handleUnauthorized() {
        console.log('Unauthorized access, redirecting to login');
        window.location.href = '/login';
    }

    if (deviceList) {
        console.log('Device list found, loading devices');

        function loadDevices() {
            fetch('/api/devices', {
                method: 'GET',
                credentials: 'same-origin'
            })
            .then(response => {
                console.log('Response status:', response.status);
                if (response.status === 401) {
                    handleUnauthorized();
                    return;
                }
                return response.json();
            })
            .then(devices => {
                if (devices) {
                    console.log('Devices loaded:', devices);
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
                credentials: 'same-origin'
            })
            .then(response => {
                console.log('Toggle device response status:', response.status);
                if (response.status === 401) {
                    handleUnauthorized();
                    return;
                }
                return response.json();
            })
            .then(data => {
                if (data && data.success) {
                    console.log('Device toggled successfully');
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
                    credentials: 'same-origin'
                })
                .then(response => {
                    console.log('Scan response status:', response.status);
                    if (response.status === 401) {
                        handleUnauthorized();
                        return;
                    }
                    return response.json();
                })
                .then(data => {
                    if (data && data.success) {
                        console.log('Scan completed successfully');
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
