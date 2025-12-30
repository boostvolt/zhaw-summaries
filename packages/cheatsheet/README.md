# cheatsheet

A Typst template for creating cheatsheets and summaries with colored sections and concept blocks.

## Usage

```typst
#import "packages/cheatsheet/src/lib.typ": *

#show: boxedsheet.with(
  title: "My Summary",
  authors: "Your Name",
  homepage: "github-username",
  num-columns: 4,
)

= Section Title
#concept-block(body: [
  #inline("Subsection")
  - Point 1
  - Point 2

  #subinline("Sub-subsection")
  More content...
])
```

## Components

| Function | Description |
|----------|-------------|
| `boxedsheet` | Main document template with header, columns, and styled headings |
| `concept-block` | Colored bordered block for grouping content |
| `inline` | Section divider with title (bold, solid lines) |
| `subinline` | Subsection divider (regular, dashed lines) |

## Parameters

### boxedsheet

| Parameter | Default | Description |
|-----------|---------|-------------|
| `title` | `[]` | Document title (shown in header) |
| `authors` | `()` | Author name(s) |
| `homepage` | `""` | Homepage/username (shown in header) |
| `font-size` | `5.5pt` | Base font size |
| `line-skip` | `5.5pt` | Spacing between lines |
| `num-columns` | `5` | Number of columns |
| `column-gutter` | `4pt` | Gap between columns |
| `x-margin` | `30pt` | Horizontal page margin |
| `y-margin` | `0pt` | Vertical page margin |
| `title-align` | `center` | Heading alignment (`left`, `center`, `right`) |
| `title-number` | `true` | Show heading numbers |
| `scaling-size` | `false` | Scale heading size by depth |
| `write-title` | `false` | Show title block at document start |

### concept-block

| Parameter | Default | Description |
|-----------|---------|-------------|
| `body` | required | Content inside the block |
| `alignment` | `start` | Content alignment |
| `width` | `100%` | Block width |
| `fill-color` | `white` | Background color |

### inline / subinline

| Parameter | Default | Description |
|-----------|---------|-------------|
| `title` | required | Section title text |
| `padding` | `true` | Add top padding |
