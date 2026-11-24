// Placeholder created by the shell so the app runs before this view lands. Owned by the logs builder.
export const view = {
  id: 'logs',
  title: 'Logs',
  icon: '',
  mount(el) {
    const note = document.createElement('p');
    note.className = 'view-loading';
    note.textContent = 'Loading view\u2026';
    el.append(note);
    return { update() {}, unmount() { el.replaceChildren(); } };
  },
};
