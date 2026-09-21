# aarora79.github.io

Source for my personal site, live at <https://aarora79.github.io/>.

Plain static HTML, no build step. GitHub Pages serves `main` from the repository root, so a push to `main` is a deploy.

## Layout

```
index.html    the whole site, one file, sections commented
404.html      not-found page
.nojekyll     tells Pages to skip Jekyll processing
```

## Editing

Everything lives in `index.html`. The sections are marked with comment banners, so search for the banner you want:

- `HERO` for the name, tagline, and intro
- `LEARNING` for the notes, wikis, and courses cards
- `BUILDING` for the open source cards
- `TEACHING`, `WRITING`, `TALKS` for the rest

Colors are CSS custom properties at the top of the `<style>` block, one set for light mode and one for dark. The palette matches the hero images on my [profile README](https://github.com/aarora79/aarora79).

Adding a card means copying one `<a class="card">` block. Adding a writing or talks entry means copying one `<li>` block, newest at the top.

## Local preview

```bash
python3 -m http.server 8000
# then open http://localhost:8000
```

## Deploy

```bash
git add -A && git commit -m "Update site" && git push
```

Pages rebuilds in under a minute. Check the Actions tab if a change does not appear.

## Related sites

Project sites published under this account, which live beneath this one:

| Site | Repo |
|---|---|
| [my-reading-list](https://aarora79.github.io/my-reading-list/) | `my-reading-list` |
| [ai-everyday-life](https://aarora79.github.io/ai-everyday-life/) | `ai-everyday-life` |
| [blueberries-in-my-salad-book](https://aarora79.github.io/blueberries-in-my-salad-book/) | `blueberries-in-my-salad-book` |
| [sb_study](https://aarora79.github.io/sb_study/) | `sb_study` |
