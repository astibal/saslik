// Hash links keep individual slides bookmarkable; without JS all slides remain readable.
const slides = [...document.querySelectorAll('.slide')];
const links = [...document.querySelectorAll('.contents a')];
const previous = document.getElementById('previous');
const next = document.getElementById('next');
let current = 0;

function showSlide() {
    const id = location.hash.slice(1) || 'overview';
    const target = document.getElementById(id);
    const selected = target?.closest('.slide') || slides[0];
    current = slides.indexOf(selected);
    slides.forEach(slide => { slide.hidden = slide !== selected; });
    links.forEach(link => {
        if (link.hash === '#' + selected.id) link.setAttribute('aria-current', 'step');
        else link.removeAttribute('aria-current');
    });
    if (target?.tagName === 'DETAILS') target.open = true;
    previous.disabled = current === 0;
    next.disabled = current === slides.length - 1;
    document.getElementById('progress').textContent = (current + 1) + ' / ' + slides.length;
    document.getElementById('pager').hidden = false;
    window.scrollTo({top: 0, behavior: 'instant'});
}
previous.addEventListener('click', () => { location.hash = slides[current - 1].id; });
next.addEventListener('click', () => { location.hash = slides[current + 1].id; });
window.addEventListener('hashchange', showSlide);
showSlide();
