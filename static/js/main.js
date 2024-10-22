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

function handleApiError(error) {
    if (error.response && error.response.status === 401) {
        // Token has expired, try to refresh
        return fetch('/refresh', { method: 'POST', credentials: 'include' })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Token refresh failed');
                }
                return response.json();
            })
            .then(data => {
                // Update the token in cookies
                document.cookie = `access_token_cookie=${data.access_token}; path=/; max-age=3600; SameSite=Lax`;
                // Retry the original request
                return fetch(error.config.url, {
                    method: error.config.method,
                    headers: {
                        'Authorization': `Bearer ${data.access_token}`
                    }
                });
            })
            .catch(() => {
                // If refresh fails, redirect to login
                window.location.href = '/login';
            });
    }
    return Promise.reject(error);
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
            },
            reconnection: true,
            reconnectionAttempts: 5
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
        });

        socket.on('devices_update', function(devices) {
            console.log('Devices update received:', devices);
            refreshDeviceList(devices);
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

    function loadDevices() {
        showLoading();
        fetch('/api/devices')
            .then(response => {
                if (!response.ok) {
                    throw response;
                }
                return response.json();
            })
            .then(devices => {
                refreshDeviceList(devices);
                hideLoading();
            })
            .catch(handleApiError)
            .then(retryResponse => {
                if (retryResponse) {
                    return retryResponse.json();
                }
            })
            .then(retriedDevices => {
                if (retriedDevices) {
                    refreshDeviceList(retriedDevices);
                }
            })
            .catch(error => {
                console.error('Error fetching devices:', error);
                if (deviceList) {
                    deviceList.innerHTML = '<tr><td colspan="7">Error loading devices. Please try again.</td></tr>';
                }
                hideLoading();
            });
    }

    if (scanButton) {
        scanButton.addEventListener('click', function() {
            showLoading();
            fetch('/api/scan', { method: 'POST' })
                .then(response => {
                    if (!response.ok) {
                        throw response;
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
                .catch(handleApiError)
                .then(retryResponse => {
                    if (retryResponse) {
                        return retryResponse.json();
                    }
                })
                .then(retriedResult => {
                    if (retriedResult && retriedResult.success) {
                        loadDevices();
                    }
                })
                .catch(error => {
                    console.error('Error during scan:', error);
                    if (deviceList) {
                        deviceList.innerHTML = '<tr><td colspan="7">Error during scan. Please try again.</td></tr>';
                    }
                    hideLoading();
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
    fetch(`/api/devices/${deviceId}/toggle`, { method: 'POST' })
        .then(response => {
            if (!response.ok) {
                throw response;
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
        .catch(handleApiError)
        .then(retryResponse => {
            if (retryResponse) {
                return retryResponse.json();
            }
        })
        .then(retriedResult => {
            if (retriedResult && retriedResult.success) {
                console.log(`Device ${deviceId} toggled successfully after retry`);
            }
        })
        .catch(error => {
            console.error('Error toggling device:', error);
        });
}
