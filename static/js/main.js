let socket;
let networkUsageChart = null;

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}

function checkAdminAccess() {
    fetchWithAuth('/admin')
        .catch(error => {
            console.error('Error accessing admin page:', error);
            window.location.href = '/login';
        });
}

function fetchWithAuth(url, options = {}) {
    options.credentials = 'include';

    return fetch(url, options)
        .then(response => {
            console.log('Response status:', response.status);
            if (response.status === 401) {
                return fetch('/refresh', { 
                    method: 'POST',
                    credentials: 'include'
                })
                .then(refreshResponse => {
                    if (!refreshResponse.ok) {
                        window.location.href = '/login';
                        throw new Error('Token refresh failed');
                    }
                    return fetch(url, options);
                })
                .catch(error => {
                    console.error('Token refresh failed:', error);
                    window.location.href = '/login';
                    throw error;
                });
            }
            if (response.status === 403) {
                window.location.href = '/login';
                throw new Error('Access forbidden');
            }
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response;
        });
}

function loadDevices() {
    const deviceList = document.getElementById('device-list');
    if (!deviceList) return;
    
    showLoading();
    fetchWithAuth('/api/devices')
        .then(response => response.json())
        .then(devices => {
            refreshDeviceList(devices);
            hideLoading();
        })
        .catch(error => {
            console.error('Error fetching devices:', error);
            if (deviceList) {
                deviceList.innerHTML = '<tr><td colspan="7">Error loading devices. Please try again.</td></tr>';
            }
            hideLoading();
        });
}

function showLoading() {
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'block';
    }
}

function hideLoading() {
    const loadingIndicator = document.getElementById('loading-indicator');
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
}

function showChartLoading() {
    const containers = document.querySelectorAll('.chart-container');
    containers.forEach(container => {
        container.innerHTML = '<div class="d-flex justify-content-center align-items-center" style="height: 300px;"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    });
}

function showChartError(message) {
    const containers = document.querySelectorAll('.chart-container');
    containers.forEach(container => {
        container.innerHTML = `<div class="alert alert-danger">${message}</div>`;
    });
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
            <td>${(device.data_usage / (1024 * 1024)).toFixed(2)} MB</td>
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
    const deviceList = document.getElementById('device-list');
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
                <td>${(device.data_usage / (1024 * 1024)).toFixed(2)} MB</td>
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

function loadNetworkUsageData(timeRange = '24h') {
    console.log('Loading network usage data for range:', timeRange);
    showChartLoading();
    
    fetchWithAuth(`/api/network_usage?range=${timeRange}`)
        .then(response => response.json())
        .then(data => {
            console.log('Network usage data received:', data);
            if (data.error) {
                throw new Error(data.error);
            }
            if (!data.labels || !data.values) {
                throw new Error('Invalid data format received');
            }
            renderNetworkUsageChart(data);
            updateNetworkStats(data);
        })
        .catch(error => {
            console.error('Error fetching network usage data:', error);
            showChartError('Error loading network usage data. Please try again later.');
        });
}

function renderNetworkUsageChart(data) {
    const ctx = document.getElementById('networkUsageChart');
    if (!ctx) return;

    const chartData = {
        labels: data.labels,
        datasets: [{
            label: 'Network Usage (MB)',
            data: data.values,
            borderColor: 'rgb(75, 192, 192)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            tension: 0.1,
            fill: true
        }]
    };

    if (networkUsageChart) {
        networkUsageChart.destroy();
    }

    networkUsageChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'hour',
                        displayFormats: {
                            hour: 'MMM d, HH:mm'
                        }
                    },
                    title: {
                        display: true,
                        text: 'Time'
                    }
                },
                y: {
                    title: {
                        display: true,
                        text: 'Usage (MB)'
                    },
                    beginAtZero: true
                }
            },
            plugins: {
                zoom: {
                    zoom: {
                        wheel: {
                            enabled: true
                        },
                        pinch: {
                            enabled: true
                        },
                        mode: 'xy'
                    },
                    pan: {
                        enabled: true,
                        mode: 'xy'
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `Usage: ${context.parsed.y.toFixed(2)} MB`;
                        }
                    }
                }
            }
        }
    });

    document.getElementById('resetZoom')?.addEventListener('click', function() {
        networkUsageChart.resetZoom();
    });
}

function updateNetworkStats(data) {
    const stats = data.statistics;
    if (!stats) return;

    const totalUsageElement = document.getElementById('totalUsage');
    const peakUsageTimeElement = document.getElementById('peakUsageTime');
    const trendElement = document.getElementById('usageTrend');

    if (totalUsageElement) {
        totalUsageElement.textContent = `${stats.total_usage.toFixed(2)} MB`;
    }

    if (peakUsageTimeElement && stats.peak_usage_time) {
        peakUsageTimeElement.textContent = stats.peak_usage_time;
    }

    if (trendElement) {
        if (stats.trend > 0) {
            trendElement.innerHTML = '<span class="text-success">↑ Increasing</span>';
        } else if (stats.trend < 0) {
            trendElement.innerHTML = '<span class="text-danger">↓ Decreasing</span>';
        } else {
            trendElement.innerHTML = '<span class="text-warning">→ Stable</span>';
        }
    }
}

function initializeTimeRangeButtons() {
    const buttons = document.querySelectorAll('.time-range-btn');
    buttons.forEach(button => {
        button.addEventListener('click', function() {
            buttons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            loadNetworkUsageData(this.dataset.range);
        });
    });
}

function initializeSocket() {
    console.log('Initializing Socket.IO');
    const socketUrl = window.location.origin;
    console.log('Connecting to WebSocket URL:', socketUrl);

    socket = io(socketUrl, {
        transports: ['websocket'],
        auth: {
            token: getCookie('access_token_cookie')
        },
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000
    });

    socket.on('connect', function() {
        console.log('Connected to WebSocket server');
    });

    socket.on('disconnect', function(reason) {
        console.log('Disconnected from WebSocket server:', reason);
    });

    socket.on('connect_error', (error) => {
        console.error('Socket connection error:', error);
        if (error.message === 'jwt expired') {
            fetch('/refresh', { 
                method: 'POST',
                credentials: 'include'
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Token refresh failed');
                }
                socket.connect();
            })
            .catch(() => {
                window.location.href = '/login';
            });
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

    socket.on('network_usage_update', function(data) {
        console.log('Network usage update received:', data);
        if (networkUsageChart) {
            networkUsageChart.data.labels = data.labels;
            networkUsageChart.data.datasets[0].data = data.values;
            networkUsageChart.update('none');
        }
        updateNetworkStats(data);
    });
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM Content Loaded');
    const path = window.location.pathname;
    const isProtectedPage = ['/devices', '/network_usage'].includes(path);

    if (isProtectedPage) {
        initializeSocket();
        if (path === '/devices') {
            loadDevices();
        } else if (path === '/network_usage') {
            loadNetworkUsageData('24h');
            initializeTimeRangeButtons();
        }
    }

    const deviceList = document.getElementById('device-list');
    const scanButton = document.getElementById('scan-button');

    if (scanButton) {
        scanButton.addEventListener('click', function() {
            showLoading();
            fetchWithAuth('/api/scan', { method: 'POST' })
                .then(response => response.json())
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
                    if (deviceList) {
                        deviceList.innerHTML = '<tr><td colspan="7">Error during scan. Please try again.</td></tr>';
                    }
                    hideLoading();
                });
        });
    }

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
    fetchWithAuth(`/api/devices/${deviceId}/toggle`, { method: 'POST' })
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