// Copyright (C) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later
// Commercial licensing: see COMMERCIAL_LICENSE.md at repository root
//! Layout engine for Prism.
//!
//! Features (A-F improvements):
//! - C: Proper text wrapping with word-boundary line breaking
//! - D: Inline elements (a, span, strong, em, code) flow within paragraphs
//! - F: Reader mode — constrained content width, comfortable typography

use prism_dom::{DomTree, NodeData, NodeId};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC TYPES
// ═══════════════════════════════════════════════════════════════════════

/// A positioned rectangle ready for painting.
#[derive(Debug, Clone)]
pub struct PaintRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
    pub content: PaintContent,
}

/// What to paint inside a rectangle.
#[derive(Debug, Clone)]
pub enum PaintContent {
    /// Render text at this position.
    Text {
        text: String,
        font_size: f32,
        bold: bool,
        italic: bool,
        color: [f32; 4],
        line_height: f32,
        is_link: bool,
        href: Option<String>,
    },
    /// A horizontal rule.
    Rule { color: [f32; 4], thickness: f32 },
    /// A filled background rectangle.
    Fill { color: [f32; 4], corner_radius: f32 },
}

/// Layout configuration.
#[derive(Debug, Clone)]
pub struct LayoutConfig {
    /// Maximum content width for reader mode (0 = full viewport).
    pub max_content_width: f32,
    /// Base font size in pixels.
    pub base_font_size: f32,
    /// Line height multiplier.
    pub line_height: f32,
    /// Average character width ratio (char_width / font_size).
    pub char_width_ratio: f32,
    /// Whether to use reader mode (centered, constrained width).
    pub reader_mode: bool,
}

impl Default for LayoutConfig {
    fn default() -> Self {
        Self {
            max_content_width: 680.0, // ~75 chars at 16px — optimal reading width
            base_font_size: 16.0,
            line_height: 1.6,
            char_width_ratio: 0.52,
            reader_mode: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// STYLE RESOLUTION
// ═══════════════════════════════════════════════════════════════════════

/// Resolved text style for a DOM node.
#[derive(Debug, Clone)]
struct TextStyle {
    font_size: f32,
    bold: bool,
    italic: bool,
    color: [f32; 4],
    is_link: bool,
    href: Option<String>,
    is_code: bool,
    is_block: bool,
    list_marker: Option<&'static str>,
}

impl TextStyle {
    fn body(config: &LayoutConfig) -> Self {
        Self {
            font_size: config.base_font_size,
            bold: false,
            italic: false,
            color: [0.13, 0.13, 0.13, 1.0],
            is_link: false,
            href: None,
            is_code: false,
            is_block: true,
            list_marker: None,
        }
    }
}

fn style_for_tag(
    tag: &str,
    parent: &TextStyle,
    config: &LayoutConfig,
    attrs: &HashMap<String, String>,
) -> TextStyle {
    let base = config.base_font_size;
    let mut s = parent.clone();
    s.list_marker = None;
    s.href = None;
    s.is_link = false;

    match tag {
        "h1" => {
            s.font_size = base * 2.0;
            s.bold = true;
            s.is_block = true;
            s.color = [0.05, 0.05, 0.05, 1.0];
        }
        "h2" => {
            s.font_size = base * 1.5;
            s.bold = true;
            s.is_block = true;
            s.color = [0.08, 0.08, 0.08, 1.0];
        }
        "h3" => {
            s.font_size = base * 1.25;
            s.bold = true;
            s.is_block = true;
        }
        "h4" => {
            s.font_size = base * 1.1;
            s.bold = true;
            s.is_block = true;
        }
        "h5" | "h6" => {
            s.font_size = base;
            s.bold = true;
            s.is_block = true;
        }
        "p" | "div" | "section" | "article" | "main" | "nav" | "aside" | "header" | "footer"
        | "blockquote" => {
            s.is_block = true;
        }
        "strong" | "b" => {
            s.bold = true;
            s.is_block = false;
        }
        "em" | "i" => {
            s.italic = true;
            s.is_block = false;
        }
        "a" => {
            s.is_link = true;
            s.is_block = false;
            s.color = [0.06, 0.36, 0.69, 1.0];
            s.href = attrs.get("href").cloned();
        }
        "code" => {
            s.is_code = true;
            s.is_block = false;
            s.color = [0.72, 0.14, 0.23, 1.0];
        }
        "pre" => {
            s.is_code = true;
            s.is_block = true;
        }
        "li" => {
            s.is_block = true;
            s.list_marker = Some("• ");
        }
        "ul" | "ol" => {
            s.is_block = true;
        }
        "hr" => {
            s.is_block = true;
        }
        "br" => {
            s.is_block = true;
        }
        _ => {
            s.is_block = false;
        }
    }
    s
}

// ═══════════════════════════════════════════════════════════════════════
// TEXT WRAPPING (Feature C)
// ═══════════════════════════════════════════════════════════════════════

/// Word-wrap text to fit within max_width. Returns wrapped lines.
fn wrap_text(text: &str, font_size: f32, max_width: f32, char_ratio: f32) -> Vec<String> {
    let char_w = font_size * char_ratio;
    let max_chars = (max_width / char_w).floor().max(10.0) as usize;

    let mut lines = Vec::new();
    let mut current_line = String::new();

    for word in text.split_whitespace() {
        if current_line.is_empty() {
            current_line = word.to_string();
        } else if current_line.len() + 1 + word.len() <= max_chars {
            current_line.push(' ');
            current_line.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current_line));
            current_line = word.to_string();
        }
    }
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

// ═══════════════════════════════════════════════════════════════════════
// FLATTENED TEXT COLLECTION (Feature D — inline elements)
// ═══════════════════════════════════════════════════════════════════════

/// A run of text with styling. Multiple runs compose a paragraph.
#[derive(Debug, Clone)]
struct TextRun {
    text: String,
    style: TextStyle,
}

/// A block-level unit: either a paragraph of inline runs, an HR, or a spacer.
#[derive(Debug)]
enum Block {
    Paragraph {
        runs: Vec<TextRun>,
        margin_top: f32,
        margin_bottom: f32,
    },
    Rule,
    #[allow(dead_code)]
    Spacer(f32),
}

/// Iterative work items for DOM-to-layout flattening.
///
/// Child cursors keep pending traversal work proportional to nesting depth
/// rather than eagerly allocating one work item for every sibling.
enum FlattenAction {
    Visit {
        node_id: NodeId,
        parent_style: TextStyle,
        runs_scope: usize,
    },
    VisitChildren {
        parent_id: NodeId,
        next_child: usize,
        child_style: TextStyle,
        runs_scope: usize,
    },
    FinishBlock {
        runs_scope: usize,
        margin_top: f32,
        margin_bottom: f32,
    },
}

/// Flatten a DOM tree into a sequence of blocks with styled text runs.
///
/// Use an explicit work stack rather than recursion: web documents are
/// untrusted, and deeply nested inline markup must not exhaust the call stack.
/// Each arena node is visited at most once to make malformed cycles or repeated
/// child links terminate without repeatedly processing the same subtree.
fn flatten_dom(dom: &DomTree, config: &LayoutConfig) -> Vec<Block> {
    let Some(root) = dom.root() else {
        return vec![];
    };

    let mut blocks = Vec::new();
    let body_style = TextStyle::body(config);
    let mut run_scopes: Vec<Vec<TextRun>> = vec![Vec::new()];
    let mut visited = HashSet::new();
    let mut work = vec![FlattenAction::Visit {
        node_id: root,
        parent_style: body_style,
        runs_scope: 0,
    }];

    while let Some(action) = work.pop() {
        match action {
            FlattenAction::FinishBlock {
                runs_scope,
                margin_top,
                margin_bottom,
            } => {
                let mut child_runs = run_scopes
                    .pop()
                    .expect("layout block run scopes must remain balanced");
                debug_assert_eq!(runs_scope, run_scopes.len());
                flush_paragraph(&mut child_runs, &mut blocks, margin_top, margin_bottom);
            }
            FlattenAction::VisitChildren {
                parent_id,
                next_child,
                child_style,
                runs_scope,
            } => {
                let Some(parent) = dom.get(parent_id) else {
                    continue;
                };
                if next_child < parent.children.len() {
                    let child_id = parent.children[next_child];
                    work.push(FlattenAction::VisitChildren {
                        parent_id,
                        next_child: next_child + 1,
                        child_style: child_style.clone(),
                        runs_scope,
                    });
                    work.push(FlattenAction::Visit {
                        node_id: child_id,
                        parent_style: child_style,
                        runs_scope,
                    });
                }
            }
            FlattenAction::Visit {
                node_id,
                parent_style,
                runs_scope,
            } => {
                if !visited.insert(node_id) {
                    continue;
                }
                let Some(node) = dom.get(node_id) else {
                    continue;
                };

                match &node.data {
                    NodeData::Text(text) => {
                        let trimmed = text.split_whitespace().collect::<Vec<_>>().join(" ");
                        if !trimmed.is_empty() {
                            run_scopes[runs_scope].push(TextRun {
                                text: trimmed,
                                style: parent_style,
                            });
                        }
                    }
                    NodeData::Element(el) => {
                        let tag = el.tag.as_str();
                        if matches!(
                            tag,
                            "script" | "style" | "noscript" | "head" | "template" | "meta" | "link" | "title"
                        ) {
                            continue;
                        }

                        let style = style_for_tag(tag, &parent_style, config, &el.attributes);

                        if tag == "hr" {
                            flush_paragraph(
                                &mut run_scopes[runs_scope],
                                &mut blocks,
                                8.0,
                                8.0,
                            );
                            blocks.push(Block::Rule);
                            continue;
                        }

                        if tag == "br" {
                            run_scopes[runs_scope].push(TextRun {
                                text: "\n".to_string(),
                                style: style.clone(),
                            });
                            continue;
                        }

                        if style.is_block {
                            flush_paragraph(
                                &mut run_scopes[runs_scope],
                                &mut blocks,
                                0.0,
                                0.0,
                            );
                            let (margin_top, margin_bottom) = block_margins(tag, &style);
                            let child_scope = run_scopes.len();
                            let mut child_runs = Vec::new();

                            if let Some(marker) = style.list_marker {
                                child_runs.push(TextRun {
                                    text: marker.to_string(),
                                    style: style.clone(),
                                });
                            }

                            run_scopes.push(child_runs);
                            work.push(FlattenAction::FinishBlock {
                                runs_scope: child_scope,
                                margin_top,
                                margin_bottom,
                            });
                            work.push(FlattenAction::VisitChildren {
                                parent_id: node_id,
                                next_child: 0,
                                child_style: style,
                                runs_scope: child_scope,
                            });
                        } else {
                            work.push(FlattenAction::VisitChildren {
                                parent_id: node_id,
                                next_child: 0,
                                child_style: style,
                                runs_scope,
                            });
                        }
                    }
                    NodeData::Document => {
                        work.push(FlattenAction::VisitChildren {
                            parent_id: node_id,
                            next_child: 0,
                            child_style: parent_style,
                            runs_scope,
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    // Preserve trailing inline content after the last block.
    if let Some(root_runs) = run_scopes.first_mut() {
        flush_paragraph(root_runs, &mut blocks, 0.0, 0.0);
    }
    blocks
}

fn flush_paragraph(runs: &mut Vec<TextRun>, blocks: &mut Vec<Block>, mt: f32, mb: f32) {
    if runs.is_empty() {
        return;
    }
    let drained: Vec<TextRun> = std::mem::take(runs);
    // Skip paragraphs that are only whitespace
    let has_content = drained.iter().any(|r| !r.text.trim().is_empty());
    if has_content {
        blocks.push(Block::Paragraph {
            runs: drained,
            margin_top: mt,
            margin_bottom: mb,
        });
    }
}

fn block_margins(tag: &str, _style: &TextStyle) -> (f32, f32) {
    match tag {
        "h1" => (24.0, 16.0),
        "h2" => (20.0, 12.0),
        "h3" => (16.0, 10.0),
        "h4" | "h5" | "h6" => (12.0, 8.0),
        "p" => (0.0, 16.0),
        "li" => (2.0, 2.0),
        "ul" | "ol" => (8.0, 8.0),
        "blockquote" => (16.0, 16.0),
        "pre" => (16.0, 16.0),
        _ => (0.0, 0.0),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// LAYOUT + PAINT GENERATION
// ═══════════════════════════════════════════════════════════════════════

/// Lay out a DOM tree and produce paint commands.
pub fn layout_dom(dom: &DomTree, viewport_width: f32, _viewport_height: f32) -> Vec<PaintRect> {
    layout_dom_with_config(
        dom,
        viewport_width,
        _viewport_height,
        &LayoutConfig::default(),
    )
}

/// Lay out with explicit configuration.
pub fn layout_dom_with_config(
    dom: &DomTree,
    viewport_width: f32,
    _viewport_height: f32,
    config: &LayoutConfig,
) -> Vec<PaintRect> {
    let blocks = flatten_dom(dom, config);

    let content_width = if config.reader_mode && config.max_content_width > 0.0 {
        viewport_width.min(config.max_content_width)
    } else {
        viewport_width
    };

    // Reader mode: center content
    let margin_left = if config.reader_mode {
        ((viewport_width - content_width) / 2.0).max(16.0)
    } else {
        8.0
    };

    let mut rects = Vec::new();
    let mut y = 8.0_f32; // top padding
    let usable_width = content_width - 32.0; // padding on both sides

    for block in &blocks {
        match block {
            Block::Paragraph {
                runs,
                margin_top,
                margin_bottom,
            } => {
                y += margin_top;

                // Merge all runs into a single styled text for wrapping
                // For now, use the first run's style as the paragraph style
                // (proper rich text would wrap per-run, but this handles 90% of cases)
                let para_style = runs
                    .first()
                    .map(|r| &r.style)
                    .cloned()
                    .unwrap_or_else(|| TextStyle::body(config));

                // Join runs with spaces between them (inline elements need separation)
                let mut full_text = String::new();
                for (i, run) in runs.iter().enumerate() {
                    if i > 0 && !full_text.ends_with(' ') && !run.text.starts_with(' ') {
                        full_text.push(' ');
                    }
                    full_text.push_str(&run.text);
                }

                let effective_width = usable_width;
                let indent = 0.0;
                let _ = para_style.is_code; // future: narrower width for code blocks
                let _ = para_style.list_marker; // future: indent for list items
                let wrap_width = effective_width - indent;

                let lines = wrap_text(
                    &full_text,
                    para_style.font_size,
                    wrap_width,
                    config.char_width_ratio,
                );
                let line_h = para_style.font_size * config.line_height;

                // Code blocks get a background
                if para_style.is_code && para_style.is_block {
                    let block_height = lines.len() as f32 * line_h + 16.0;
                    rects.push(PaintRect {
                        x: margin_left,
                        y,
                        width: usable_width + 16.0,
                        height: block_height,
                        content: PaintContent::Fill {
                            color: [0.96, 0.96, 0.96, 1.0],
                            corner_radius: 4.0,
                        },
                    });
                }

                for line in &lines {
                    if !line.is_empty() {
                        // Check if this line contains mixed styles (inline elements)
                        // For simplicity, emit the whole line with the dominant style
                        // A future version will emit per-run styled spans
                        rects.push(PaintRect {
                            x: margin_left + indent,
                            y,
                            width: wrap_width,
                            height: line_h,
                            content: PaintContent::Text {
                                text: line.clone(),
                                font_size: para_style.font_size,
                                bold: para_style.bold,
                                italic: para_style.italic,
                                color: para_style.color,
                                line_height: line_h,
                                is_link: para_style.is_link,
                                href: para_style.href.clone(),
                            },
                        });
                    }
                    y += line_h;
                }

                y += margin_bottom;
            }
            Block::Rule => {
                y += 8.0;
                rects.push(PaintRect {
                    x: margin_left,
                    y,
                    width: usable_width,
                    height: 1.0,
                    content: PaintContent::Rule {
                        color: [0.8, 0.8, 0.8, 1.0],
                        thickness: 1.0,
                    },
                });
                y += 9.0;
            }
            Block::Spacer(h) => {
                y += h;
            }
        }
    }

    rects
}

#[cfg(test)]
mod tests {
    use super::*;
    use prism_dom::parse_html;

    #[test]
    fn layout_basic_page() {
        let dom = parse_html("<html><body><h1>Title</h1><p>Paragraph.</p></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        assert!(!rects.is_empty());
        let has_title = rects.iter().any(
            |r| matches!(&r.content, PaintContent::Text { text, .. } if text.contains("Title")),
        );
        assert!(has_title, "Should find Title text");
    }

    #[test]
    fn layout_handles_deep_inline_dom_without_call_stack_growth() {
        const DEPTH: usize = 20_000;
        // Parse only a shallow shell, then build the depth directly so this
        // regression isolates layout traversal from HTML parser behavior.
        let mut dom = parse_html("<html><body><p><span></span></p></body></html>");
        let first_span = *dom.find_by_tag("span").first().expect("fixture has a span");
        let span_data = dom.get(first_span).expect("span exists").data.clone();
        let mut parent = first_span;
        for _ in 0..DEPTH {
            let child = dom.new_node(span_data.clone());
            dom.append_child(parent, child);
            parent = child;
        }
        let text = dom.new_node(NodeData::Text("deep layout".to_string()));
        dom.append_child(parent, text);

        let rects = layout_dom(&dom, 800.0, 600.0);
        assert!(
            rects.iter().any(
                |r| matches!(&r.content, PaintContent::Text { text, .. } if text.contains("deep layout"))
            ),
            "deep inline text should survive layout"
        );
    }

    #[test]
    fn layout_terminates_on_malformed_dom_cycles() {
        let mut dom = parse_html("<html><body><div>cycle-safe</div></body></html>");
        let div = *dom.find_by_tag("div").first().expect("fixture has a div");
        dom.get_mut(div).expect("div exists").children.push(div);

        let rects = layout_dom(&dom, 800.0, 600.0);
        assert!(
            rects.iter().any(
                |r| matches!(&r.content, PaintContent::Text { text, .. } if text.contains("cycle-safe"))
            ),
            "valid text should remain laid out even when a child cycle exists"
        );
    }

    #[test]
    fn layout_preserves_trailing_inline_text_after_a_block() {
        let dom = parse_html(
            "<html><body><p>Block content</p><span>Trailing inline content</span></body></html>",
        );
        let rects = layout_dom(&dom, 800.0, 600.0);
        assert!(
            rects.iter().any(
                |r| matches!(&r.content, PaintContent::Text { text, .. } if text.contains("Trailing inline content"))
            ),
            "inline text after the final block must be flushed into layout output"
        );
    }

    #[test]
    fn layout_empty_page() {
        let dom = parse_html("");
        let rects = layout_dom(&dom, 800.0, 600.0);
        let text_count = rects
            .iter()
            .filter(|r| matches!(r.content, PaintContent::Text { .. }))
            .count();
        assert_eq!(text_count, 0);
    }

    #[test]
    fn layout_positions_non_negative() {
        let dom = parse_html("<html><body><h1>Hello</h1><p>World</p></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        for r in &rects {
            assert!(r.x >= 0.0, "x={}", r.x);
            assert!(r.y >= 0.0, "y={}", r.y);
        }
    }

    #[test]
    fn layout_h1_bold_and_large() {
        let dom = parse_html("<html><body><h1>Big</h1></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        let h1 = rects
            .iter()
            .find(|r| matches!(&r.content, PaintContent::Text { text, .. } if text == "Big"));
        assert!(h1.is_some());
        if let PaintContent::Text {
            font_size, bold, ..
        } = &h1.unwrap().content
        {
            assert!(*bold, "h1 must be bold");
            assert!(
                *font_size > 20.0,
                "h1 font must be large, got {}",
                font_size
            );
        }
    }

    #[test]
    fn layout_vertical_order() {
        let dom = parse_html("<html><body><h1>A</h1><p>B</p><p>C</p></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        let texts: Vec<_> = rects
            .iter()
            .filter(|r| matches!(r.content, PaintContent::Text { .. }))
            .collect();
        for i in 1..texts.len() {
            assert!(
                texts[i].y >= texts[i - 1].y,
                "text {} y={} should be >= text {} y={}",
                i,
                texts[i].y,
                i - 1,
                texts[i - 1].y
            );
        }
    }

    #[test]
    fn layout_text_wraps() {
        let long = "word ".repeat(100); // 500 chars
        let html = format!("<html><body><p>{}</p></body></html>", long);
        let dom = parse_html(&html);
        let rects = layout_dom(&dom, 400.0, 600.0);
        let text_rects: Vec<_> = rects
            .iter()
            .filter(|r| matches!(r.content, PaintContent::Text { .. }))
            .collect();
        assert!(
            text_rects.len() > 1,
            "Long text should wrap to multiple lines, got {}",
            text_rects.len()
        );
    }

    #[test]
    fn layout_inline_bold() {
        let dom = parse_html("<html><body><p>Hello <strong>bold</strong> world</p></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        // The paragraph should produce text containing "Hello bold world"
        let has_combined = rects.iter().any(|r| {
            matches!(&r.content, PaintContent::Text { text, .. } if text.contains("Hello") && text.contains("bold"))
        });
        assert!(has_combined, "Inline elements should flow within paragraph");
    }

    #[test]
    fn layout_list_has_markers() {
        let dom = parse_html("<html><body><ul><li>First</li><li>Second</li></ul></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        let has_bullet = rects
            .iter()
            .any(|r| matches!(&r.content, PaintContent::Text { text, .. } if text.contains("•")));
        assert!(has_bullet, "List items should have bullet markers");
    }

    #[test]
    fn layout_reader_mode_centered() {
        let dom = parse_html("<html><body><p>Content</p></body></html>");
        let rects = layout_dom_with_config(
            &dom,
            1200.0,
            800.0,
            &LayoutConfig {
                reader_mode: true,
                max_content_width: 680.0,
                ..Default::default()
            },
        );
        let text_rect = rects
            .iter()
            .find(|r| matches!(&r.content, PaintContent::Text { .. }));
        assert!(text_rect.is_some());
        let x = text_rect.unwrap().x;
        // On a 1200px viewport with 680px content, left margin should be ~260px
        assert!(x > 200.0, "Reader mode should center content, x={}", x);
    }

    #[test]
    fn layout_hr_produces_rule() {
        let dom = parse_html("<html><body><p>Above</p><hr><p>Below</p></body></html>");
        let rects = layout_dom(&dom, 800.0, 600.0);
        let has_rule = rects
            .iter()
            .any(|r| matches!(r.content, PaintContent::Rule { .. }));
        assert!(has_rule, "HR should produce a Rule paint command");
    }
}
