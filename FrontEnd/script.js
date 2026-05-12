document.addEventListener('DOMContentLoaded', () => {
    // Smooth scrolling for navigation links
    document.querySelectorAll('nav .nav-links a').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const href = this.getAttribute('href');

            // Only intercept internal hash navigation for smooth scroll
            if (href && href.startsWith('#')) {
                e.preventDefault();

                const targetId = href.substring(1);
                const targetElement = document.getElementById(targetId);

                if (targetElement) {
                    const navbarHeight = document.querySelector('.navbar').offsetHeight;
                    const offsetTop = targetElement.getBoundingClientRect().top + window.scrollY - navbarHeight;

                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            }
        });
    });

    // Interactive Demo Section Logic
    const scanVendorBtn = document.getElementById('scanVendorBtn');
    const vendorNameInput = document.getElementById('vendorNameInput');
    const scanResultDiv = document.getElementById('scanResult');

    scanVendorBtn.addEventListener('click', () => {
        const vendorName = vendorNameInput.value.trim();
        if (vendorName === "") {
            scanResultDiv.innerHTML = '<p style="color: #FF6347;">Please enter a vendor name.</p>';
            return;
        }

        // Simulate API call with a delay
        scanResultDiv.innerHTML = '<p><i class="fas fa-spinner fa-spin"></i> Analyzing...</p>';

        setTimeout(() => {
            const riskScore = Math.floor(Math.random() * 100) + 1; // 1-100
            let riskLevel = '';
            let riskClass = '';

            if (riskScore >= 80) {
                riskLevel = 'Low';
                riskClass = 'risk-low';
            } else if (riskScore >= 40) {
                riskLevel = 'Medium';
                riskClass = 'risk-medium';
            } else {
                riskLevel = 'High';
                riskClass = 'risk-high';
            }

            scanResultDiv.innerHTML = `
                <p><strong>Vendor Name:</strong> ${vendorName}</p>
                <p><strong>Risk Score:</strong> ${riskScore}</p>
                <p><strong>Risk Level:</strong> <span class="risk-level-display ${riskClass}">${riskLevel}</span></p>
            `;
        }, 1500); // Simulate 1.5 seconds loading time
    });

    // Optional: Add more animations / scroll effects if needed
    // Example: Fade in sections on scroll (requires Intersection Observer API)

    // const faders = document.querySelectorAll('.card, .hero-content, .hero-right');
    // const appearOptions = {
    //     threshold: 0.3,
    //     rootMargin: "0px 0px -50px 0px"
    // };

    // const appearOnScroll = new IntersectionObserver(function(entries, appearOnScroll) {
    //     entries.forEach(entry => {
    //         if (!entry.isIntersecting) {
    //             return;
    //         } else {
    //             entry.target.classList.add('appear');
    //             appearOnScroll.unobserve(entry.target);
    //         }
    //     });
    // }, appearOptions);

    // faders.forEach(fader => {
    //     appearOnScroll.observe(fader);
    // });
});
