// script.js – handles navigation toggle, contact form alert, and PhishGuard URL checker

// Mobile navigation toggle
const navToggle = document.getElementById('navToggle');
const navMenu = document.getElementById('navMenu');
if (navToggle && navMenu) {
  navToggle.addEventListener('click', () => {
    navMenu.querySelector('ul').classList.toggle('show');
  });
}

// Contact form handling (frontend only)
const contactForm = document.getElementById('contactForm');
if (contactForm) {
  contactForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const name = contactForm.name.value.trim();
    const email = contactForm.email.value.trim();
    const message = contactForm.message.value.trim();
    if (name && email && message) {
      alert('Thank you, ' + name + '! Your message has been received.');
      contactForm.reset();
    } else {
      alert('Please fill out all fields before submitting.');
    }
  });
}

// PhishGuard URL checker – opens external site in a new tab
const phishBtn = document.getElementById('phish-analyze');
if (phishBtn) {
  phishBtn.addEventListener('click', () => {
    const urlInput = document.getElementById('phish-url');
    const url = urlInput ? urlInput.value.trim() : '';
    // The URL is not sent to the external service; we simply open the tool site.
    window.open('https://phishguard-siva-ml.onrender.com', '_blank');
  });
}
