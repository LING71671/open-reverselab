from pathlib import Path

from conftest import ROOT, load_script_module

llms = load_script_module("scripts/misc/generate_llms_txt.py", "kb_llms_test")


def test_folded_summary_stops_at_next_frontmatter_field():
    content = '---\nsummary: >\n  First line.\n  Second line.\nsummary_en: "English summary"\n---\nBody'
    assert llms._get_frontmatter_field(content, "summary") == "First line. Second line."
    assert llms._get_frontmatter_field(content, "summary_en") == "English summary"


def test_llm_catalog_publishes_all_tracks_and_both_networks():
    articles = llms.collect_articles()
    networks = llms.collect_articles(networks=True)
    assert {article["track"] for article in articles} == {"red", "blue", "shared"}
    assert len(networks) == 8
    assert len({article["path"] for article in articles + networks}) == len(articles) + len(networks)
    for article in articles + networks:
        path = Path(article["path"])
        assert path.is_file()
        expected = path.relative_to(ROOT).with_suffix('.html').as_posix()
        assert article["url"] == llms.SITE_URL + expected
    compact = llms.generate_llms_txt(articles, networks)
    assert all(article["url"] in compact for article in networks)


def test_full_dump_keeps_article_tail(tmp_path):
    path = tmp_path / "long.md"
    path.write_text('# Long\n' + 'Evidence. ' * 1200 + '\nFinal conclusion', encoding='utf-8')
    text = llms.generate_llms_full([dict(board='general', title='Long', title_en='', url='', github_url='', summary='', path=str(path))])
    assert 'Final conclusion' in text
