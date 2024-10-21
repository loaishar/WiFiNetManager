function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function checkAuthentication() {
    const token = getCookie('access_token_cookie');
    if (!token) {
        window.location.href = '/login';
    }
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    checkAuthentication();

    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');
    const loadingIndicator = document.getElementById('loading-indicator');

    let socket;

    function initializeSocket() {
        console.log('Initializing Socket.IO');

        const token = getCookie('access_token_cookie');
        const socketUrl = window.location.origin;

        console.log('Connecting to WebSocket URL:', socketUrl);

        socket = io(socketUrl, {
            transports: ['websocket'],
            auth: {
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
            if (error.message === 'Unauthorized') {
                window.location.href = '/login';
            }
        });

        socket.on('device_updated', function(device) {
            console.log('Device update received:', device);
            updateDeviceInList(device);
            updateNetworkUsage(device);
        });

        socket.on('devices_update', function(devices) {
            console.log('Devices update received:', devices);
            refreshDeviceList(devices);
            updateNetworkUsageList(devices);
        });

        socket.on('error', function(error) {
            console.error('WebSocket error:', error);
            if (error.message === 'Unauthorized') {
                window.location.href = '/login';
            }
        });
    }

    initializeSocket();

    function showLoading() {
        if (loadingIndicator) {
            loadingIndicator.style.display = 'block';
        }
    }

    function hideLoading() {
        if (loadingIndicator) {
            loadingIndicator.style.display = 'none';
        }
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
                <td>${(device.data_usage / 1024 / 1024).toFixed(2)} MB</td>
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
        if (!deviceList) return;
        
        if (devices.length === 0) {
            deviceList.innerHTML = '<tr><td colspan="7">No devices found. Try scanning for new devices.</td></tr>';
        } else {
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
                    <td>${(device.data_usage / 1024 / 1024).toFixed(2)} MB</td>
                    <td>
                        <button class="btn ${device.blocked ? 'btn-success' : 'btn-danger'} btn-sm toggle-device" data-device-id="${device.id}">
                            ${device.blocked ? 'Unblock' : 'Block'}
                        </button>
                    </td>
                `;
                deviceList.appendChild(row);
            });
        }
    }

    function updateNetworkUsage(device) {
        const usageListItem = document.querySelector(`#device-list li[data-device-id="${device.id}"]`);
        if (usageListItem) {
            const usageBadge = usageListItem.querySelector('.badge');
            usageBadge.textContent = `${(device.data_usage / 1024 / 1024).toFixed(2)} MB`;
        }
    }

    function updateNetworkUsageList(devices) {
        const usageList = document.getElementById('device-list');
        if (usageList) {
            usageList.innerHTML = '';
            devices.forEach(device => {
                const listItem = document.createElement('li');
                listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
                listItem.dataset.deviceId = device.id;
                listItem.innerHTML = `
                    ${device.name}
                    <span class="badge bg-primary rounded-pill">${(device.data_usage / 1024 / 1024).toFixed(2)} MB</span>
                `;
                usageList.appendChild(listItem);
            });
        }
    }

    function loadDevices() {
        showLoading();
        fetch('/api/devices')
            .then(response => {
                if (response.status === 401) {
                    window.location.href = '/login';
                    throw new Error('Unauthorized');
                }
                return response.json();
            })
            .then(devices => {
                refreshDeviceList(devices);
                updateNetworkUsageList(devices);
                hideLoading();
            })
            .catch(error => {
                console.error('Error fetching devices:', error);
                if (error.message !== 'Unauthorized') {
                    if (deviceList) {
                        deviceList.innerHTML = '<tr><td colspan="7">Error loading devices. Please try again.</td></tr>';
                    }
                    hideLoading();
                }
            });
    }

    if (scanButton) {
        scanButton.addEventListener('click', function() {
            showLoading();
            fetch('/api/scan', { method: 'POST' })
                .then(response => {
                    if (response.status === 401) {
                        window.location.href = '/login';
                        throw new Error('Unauthorized');
                    }
                    return response.json();
                })
                .then(result => {
                    if (result.success) {
                        loadDevices();
                    } else {
                        console.error('Scan failed:', result.error);
                        if (deviceList) {
                            deviceList.innerHTML = '<tr><td colspan="7">Scan failed. Please try again.</td></tr>';
                        }
                    }
                    hideLoading();
                })
                .catch(error => {
                    console.error('Error during scan:', error);
                    if (error.message !== 'Unauthorized') {
                        if (deviceList) {
                            deviceList.innerHTML = '<tr><td colspan="7">Error during scan. Please try again.</td></tr>';
                        }
                        hideLoading();
                    }
                });
        });
    }

    loadDevices();

    if (deviceList) {
        deviceList.addEventListener('click', function(event) {
            if (event.target.classList.contains('toggle-device')) {
                const deviceId = event.target.getAttribute('data-device-id');
                toggleDevice(deviceId);
            }
        });
    }
});

function toggleDevice(deviceId) {
    const confirmModal = new bootstrap.Modal(document.getElementById('confirmModal'));
    const confirmModalBody = document.getElementById('confirmModalBody');
    const confirmModalYes = document.getElementById('confirmModalYes');

    if (confirmModalBody) {
        confirmModalBody.textContent = 'Are you sure you want to toggle this device?';
    }
    
    if (confirmModalYes) {
        confirmModalYes.onclick = function() {
            confirmModal.hide();
            executeToggleDevice(deviceId);
        };
    }

    confirmModal.show();
}

function executeToggleDevice(deviceId) {
    fetch(`/api/devices/${deviceId}/toggle`, { method: 'POST' })
        .then(response => {
            if (response.status === 401) {
                window.location.href = '/login';
                throw new Error('Unauthorized');
            }
            return response.json();
        })
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
