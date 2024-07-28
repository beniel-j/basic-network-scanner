document.getElementById('scanButton').addEventListener('click', function() {
    document.getElementById('results').textContent = 'Scanning... Please wait.';
    fetch('/scan')
        .then(response => response.json())
        .then(data => {
            let results = 'No anomalies detected.';
            if (data.anomalies.length > 0) {
                results = 'Anomalous behavior detected:\n';
                data.anomalies.forEach(anomaly => {
                    results += `Source: ${anomaly.src_ip}, Destination: ${anomaly.dst_ip}, Length: ${anomaly.length}\n`;
                });
            }
            document.getElementById('results').textContent = results;
        })
        .catch(error => {
            console.error('Error:', error);
            document.getElementById('results').textContent = 'An error occurred.';
        });
});
