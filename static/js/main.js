function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

document.addEventListener('DOMContentLoaded', function() {
    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');
    const loadingIndicator = document.getElementById('loading-indicator');

    console.log('DOM Content Loaded');

    let socket;

    function initializeSocket() {
        console.log('Initializing Socket.IO');

        const token = getCookie('access_token_cookie');
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.hostname;
        const port = window.location.port || (protocol === 'wss:' ? '443' : '80');
        const socketUrl = `${protocol}//${host}:${port}`;

        console.log('Connecting to WebSocket URL:', socketUrl);

        socket = io(socketUrl, {
            transports: ['websocket'],
            auth: {
                token: token
            },
            query: {
                token: token
            }
        });

        socket.on('connect', function() {
            console.log('Connected to WebSocket server');
        });

        socket.on('disconnect', function(reason) {
            console.log('Disconnected from WebSocket server:', reason);
        });

        socket.on('connect_error', function(error) {
            console.error('Connection error:', error.message);
        });

        socket.on('device_updated', function(device) {
            console.log('Device update received:', device);
            updateDeviceInList(device);
        });

        socket.on('devices_update', function(devices) {
            console.log('Devices update received:', devices);
            refreshDeviceList(devices);
        });

        socket.on('error', function(error) {
            console.error('WebSocket error:', error);
        });
    }

    initializeSocket();

    function showLoading() {
        loadingIndicator.style.display = 'block';
    }

    function hideLoading() {
        loadingIndicator.style.display = 'none';
    }

    function updateDeviceInList(device) {
        const deviceRow = document.getElementById(`device-${device.id}`);
        if (deviceRow) {
            deviceRow.innerHTML = `
                <td>${device.name}</td>
                <td>${device.ip_address}</td>
                <td>${device.mac_address}</td>
                <td>${device.status ? 'Online' : 'Offline'}</td>
                <td>${device.last_seen}</td>
                <td>
                    <button class="btn ${device.blocked ? 'btn-success' : 'btn-danger'} btn-sm toggle-device" data-device-id="${device.id}">
                        ${device.blocked ? 'Unblock' : 'Block'}
                    </button>
                </td>
            `;
        } else {
            refreshDeviceList([device]);
        }
    }

    function refreshDeviceList(devices) {
        deviceList.innerHTML = '';
        devices.forEach(device => {
            const row = document.createElement('tr');
            row.id = `device-${device.id}`;
            row.innerHTML = `
                <td>${device.name}</td>
                <td>${device.ip_address}</td>
                <td>${device.mac_address}</td>
                <td>${device.status ? 'Online' : 'Offline'}</td>
                <td>${device.last_seen}</td>
                <td>
                    <button class="btn ${device.blocked ? 'btn-success' : 'btn-danger'} btn-sm toggle-device" data-device-id="${device.id}">
                        ${device.blocked ? 'Unblock' : 'Block'}
                    </button>
                </td>
            `;
            deviceList.appendChild(row);
        });
    }

    function loadDevices() {
        showLoading();
        fetch('/api/devices')
            .then(response => response.json())
            .then(devices => {
                refreshDeviceList(devices);
                hideLoading();
            })
            .catch(error => {
                console.error('Error fetching devices:', error);
                hideLoading();
            });
    }

    if (scanButton) {
        scanButton.addEventListener('click', function() {
            showLoading();
            fetch('/api/scan', { method: 'POST' })
                .then(response => response.json())
                .then(result => {
                    if (result.success) {
                        loadDevices();
                    } else {
                        console.error('Scan failed:', result.error);
                    }
                    hideLoading();
                })
                .catch(error => {
                    console.error('Error during scan:', error);
                    hideLoading();
                });
        });
    }

    loadDevices();

    deviceList.addEventListener('click', function(event) {
        if (event.target.classList.contains('toggle-device')) {
            const deviceId = event.target.getAttribute('data-device-id');
            toggleDevice(deviceId);
        }
    });
});

function toggleDevice(deviceId) {
    const confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
    const confirmModalBody = document.getElementById('confirmModalBody');
    const confirmModalYes = document.getElementById('confirmModalYes');

    confirmModalBody.textContent = 'Are you sure you want to toggle this device?';
    
    confirmModalYes.onclick = function() {
        confirmModal.hide();
        executeToggleDevice(deviceId);
    };

    confirmModal.show();
}

function executeToggleDevice(deviceId) {
    fetch(`/api/devices/${deviceId}/toggle`, { method: 'POST' })
        .then(response => response.json())
        .then(result => {
            if (result.success) {
                console.log(`Device ${deviceId} toggled successfully`);
            } else {
                console.error('Error toggling device:', result.error);
            }
        })
        .catch(error => {
            console.error('Error toggling device:', error);
        });
}
