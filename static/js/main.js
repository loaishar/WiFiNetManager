document.addEventListener('DOMContentLoaded', function() {
    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');
    const loadingIndicator = document.getElementById('loading-indicator');

    console.log('DOM Content Loaded');

    // Initialize Socket.IO with explicit configuration
    let socket;
    try {
        socket = io('http://' + document.domain + ':' + location.port);
        console.log('Socket.IO initialized');
    } catch (error) {
        console.error('Error initializing Socket.IO:', error);
    }

    if (socket) {
        socket.on('connect', function() {
            console.log('Connected to WebSocket');
        });

        socket.on('disconnect', function() {
            console.log('Disconnected from WebSocket');
        });

        socket.on('device_update', function(device) {
            console.log('Device update received:', device);
            updateDeviceInList(device);
        });

        socket.on('devices_update', function(devices) {
            console.log('Devices update received:', devices);
            refreshDeviceList(devices);
        });

        socket.on('connect_error', (error) => {
            console.error('Socket.IO connection error:', error);
        });
    }

    function handleUnauthorized() {
        console.log('Unauthorized access, redirecting to login');
        window.location.href = '/login';
    }

    function showLoading(show) {
        loadingIndicator.style.display = show ? 'block' : 'none';
    }

    function updateDeviceInList(device) {
        console.log('Updating device in list:', device);
        const row = document.querySelector(`#device-list tr[data-device-id="${device.id}"]`);
        if (row) {
            const lastSeen = device.last_seen ? new Date(device.last_seen).toLocaleString() : 'N/A';
            row.innerHTML = `
                <td>${device.name}</td>
                <td>${device.ip_address}</td>
                <td>${device.mac_address}</td>
                <td>${device.status ? 'Online' : 'Offline'}</td>
                <td>${lastSeen}</td>
                <td>
                    <button class="btn btn-sm ${device.blocked ? 'btn-danger' : 'btn-success'}" onclick="toggleDevice(${device.id}, '${device.name}', ${device.blocked})">
                        ${device.blocked ? 'Unblock' : 'Block'}
                    </button>
                </td>
            `;
        } else {
            console.log('Device not found in list, reloading all devices');
            loadDevices();
        }
    }

    function refreshDeviceList(devices) {
        deviceList.innerHTML = '';
        devices.forEach(device => {
            const row = document.createElement('tr');
            row.setAttribute('data-device-id', device.id);
            const lastSeen = device.last_seen ? new Date(device.last_seen).toLocaleString() : 'N/A';
            row.innerHTML = `
                <td>${device.name}</td>
                <td>${device.ip_address}</td>
                <td>${device.mac_address}</td>
                <td>${device.status ? 'Online' : 'Offline'}</td>
                <td>${lastSeen}</td>
                <td>
                    <button class="btn btn-sm ${device.blocked ? 'btn-danger' : 'btn-success'}" onclick="toggleDevice(${device.id}, '${device.name}', ${device.blocked})">
                        ${device.blocked ? 'Unblock' : 'Block'}
                    </button>
                </td>
            `;
            deviceList.appendChild(row);
        });
    }

    if (deviceList) {
        console.log('Device list found, loading devices');

        function loadDevices() {
            showLoading(true);
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
                showLoading(false);
                if (devices) {
                    console.log('Devices loaded:', devices);
                    refreshDeviceList(devices);
                }
            })
            .catch(error => {
                showLoading(false);
                console.error('Error fetching devices:', error);
                alert('Failed to load devices. Please try again.');
            });
        }

        loadDevices();

        window.toggleDevice = function(deviceId, deviceName, isBlocked) {
            const action = isBlocked ? 'unblock' : 'block';
            const modalBody = document.getElementById('confirmModalBody');
            modalBody.textContent = `Are you sure you want to ${action} the device "${deviceName}"?`;

            const confirmYes = document.getElementById('confirmModalYes');
            confirmYes.onclick = function() {
                executeToggleDevice(deviceId);
                const modal = bootstrap.Modal.getInstance(document.getElementById('confirmModal'));
                modal.hide();
            };

            const modal = new bootstrap.Modal(document.getElementById('confirmModal'));
            modal.show();
        };

        function executeToggleDevice(deviceId) {
            showLoading(true);
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
                showLoading(false);
                if (data && data.success) {
                    console.log('Device toggled successfully');
                } else {
                    throw new Error('Failed to toggle device status');
                }
            })
            .catch(error => {
                showLoading(false);
                console.error('Error toggling device:', error);
                alert(error.message || 'An error occurred. Please try again.');
            });
        }

        if (scanButton) {
            scanButton.addEventListener('click', function() {
                console.log('Scan button clicked');
                showLoading(true);
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
                    showLoading(false);
                    if (data && data.success) {
                        console.log('Scan completed successfully');
                    } else {
                        throw new Error('Failed to scan for new devices');
                    }
                })
                .catch(error => {
                    showLoading(false);
                    console.error('Error scanning devices:', error);
                    alert(error.message || 'An error occurred while scanning. Please try again.');
                });
            });
        }
    }
});