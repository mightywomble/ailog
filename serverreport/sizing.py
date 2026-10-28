"""Work out how much model capacity a report actually needs.

Two questions are answered here:

1. **How big is this report?** - derived from the evidence pack itself plus the
   cluster/event counts, which is far more honest than guessing from log volume.
2. **What should we run it with?** - a recommended depth (evidence budget +
   output budget + chunking threshold) and, when the selected model cannot hold
   the pack, a bigger-context model.

The point is to stop guessing: a quiet 15-minute window should not be treated
like a 24-hour all-sources run, and a model with a 32k context should not be
handed a 60k-token pack and asked to "summarise it well".
"""
import math

# Depth levels: each is an evidence budget (prompt side) and an output budget
# (completion side), plus the point at which map-reduce chunking kicks in.
DEPTHS = {
    1: {'key': 'lite', 'label': 'Lite', 'evidence_tokens': 4000, 'max_output_tokens': 1200,
        'chunk_at': 6000, 'description': 'Headline verdict and top correlations only.'},
    2: {'key': 'standard', 'label': 'Standard', 'evidence_tokens': 8000, 'max_output_tokens': 2000,
        'chunk_at': 10000, 'description': 'Normal report: timeline, root causes, actions.'},
    3: {'key': 'detailed', 'label': 'Detailed', 'evidence_tokens': 12000, 'max_output_tokens': 3000,
        'chunk_at': 14000, 'description': 'More clusters, more evidence, fuller timeline.'},
    4: {'key': 'deep', 'label': 'Deep', 'evidence_tokens': 20000, 'max_output_tokens': 4200,
        'chunk_at': 22000, 'description': 'Wide evidence budget; chunked if needed.'},
    5: {'key': 'maximum', 'label': 'Maximum', 'evidence_tokens': 32000, 'max_output_tokens': 6000,
        'chunk_at': 34000, 'description': 'Everything we can fit; always chunked on big hosts.'},
}

DEFAULT_DEPTH = 3
AUTO_DEPTH = 0

# Rough context windows, in tokens. Unknown models get a conservative default so
# we under-fill rather than get a 400 from the provider.
MODEL_CONTEXTS = (
    ('gpt-4o', 128000),
    ('gpt-4.1', 128000),
    ('gpt-4-turbo', 128000),
    ('gpt-3.5-turbo', 16385),
    ('o1', 200000),
    ('o3', 200000),
    ('claude', 200000),
    ('gemini', 1000000),
    ('deepseek', 65536),
    ('llama', 128000),
    ('qwen', 32768),
    ('mistral', 32768),
)
FALLBACK_CONTEXT = 32768
# Leave room for the system prompt, the answer and tokenizer drift.
SAFETY_MARGIN = 0.75


def model_context(model):
    name = (model or '').lower()
    for needle, ctx in MODEL_CONTEXTS:
        if needle in name:
            return ctx
    return FALLBACK_CONTEXT


def usable_context(model):
    """Tokens we are willing to spend on input for this model."""
    return int(model_context(model) * SAFETY_MARGIN)


def depth_profile(depth):
    try:
        depth = int(depth)
    except (TypeError, ValueError):
        depth = DEFAULT_DEPTH
    if depth not in DEPTHS:
        depth = DEFAULT_DEPTH
    return dict(DEPTHS[depth], depth=depth)


def scaled_profile(depth, model):
    """Depth profile capped by what the model can actually hold."""
    profile = depth_profile(depth)
    limit = usable_context(model)
    # Always keep headroom for the completion.
    cap = max(2000, limit - profile['max_output_tokens'])
    if profile['evidence_tokens'] > cap:
        profile['evidence_tokens'] = cap
        profile['chunk_at'] = max(profile['chunk_at'], cap)
    return profile


def _verdict_hint(severity):
    crit = severity.get('crit', 0)
    error = severity.get('error', 0)
    if crit or error > 50:
        return 'high'
    if error > 5:
        return 'medium'
    return 'low'


def recommend(stats, model, requested_depth=None):
    """Recommend depth, chunking and model for this run.

    ``stats`` needs: pack_tokens (full, untrimmed), events, clusters, sources,
    severity, correlations.
    """
    pack_tokens = int(stats.get('pack_tokens') or 0)
    events = int(stats.get('events') or 0)
    clusters = int(stats.get('clusters') or 0)
    sources = int(stats.get('sources') or 0)
    correlations = int(stats.get('correlations') or 0)
    severity = stats.get('severity') or {}
    username = stats.get('model_filtered') or 'the selected model'

    usable = usable_context(model)
    selected = depth_profile(requested_depth) if requested_depth else None

    # Size the run from the pack itself: that is what the model actually sees.
    auto_depth = DEFAULT_DEPTH
    if pack_tokens <= 3500:
        auto_depth = 1
    elif pack_tokens <= 7000:
        auto_depth = 2
    elif pack_tokens <= 12000:
        auto_depth = 3
    elif pack_tokens <= 20000:
        auto_depth = 4
    else:
        auto_depth = 5

    # Busy or noisy hosts deserve the next level up, regardless of pack size:
    # more clusters means more of the tail is worth showing.
    if clusters > 400 or events > 20000:
        auto_depth = min(5, auto_depth + 1)
    if correlations >= 10 and auto_depth < 4:
        auto_depth = min(5, auto_depth + 1)

    # An explicit request always wins; auto only fills the gap.
    depth = selected['depth'] if selected else auto_depth

    profile = scaled_profile(depth, model)
    chunks = 1
    if pack_tokens > profile['chunk_at']:
        chunks = int(math.ceil(pack_tokens / max(1, profile['evidence_tokens'])))
        chunks = max(2, chunks)

    needs_bigger_model = pack_tokens > usable
    suggested_model = model
    if needs_bigger_model:
        suggested_model = suggest_model(pack_tokens)

    rationale = []
    rationale.append(f'{events:,} events reduced to {clusters:,} signatures from {sources} sources.')
    rationale.append(f'Evidence pack is ~{pack_tokens:,} tokens; {username} holds ~{usable:,} input tokens.')
    if chunks > 1:
        rationale.append(f'That fits in {chunks} chunks, so it will be summarised in {chunks} passes then merged.')
    if needs_bigger_model:
        rationale.append(f'It exceeds the model context; {suggested_model} has more room.')
    if selected and selected['depth'] != auto_depth:
        rationale.append(
            f'You chose {selected["label"]}; evidence size would have suggested '
            f'{DEPTHS[auto_depth]["label"]}.'
        )
    if _verdict_hint(severity) == 'high':
        rationale.append('Error volume is high, so depth is weighted up.')

    return {
        'depth': depth,
        'depth_label': DEPTHS[depth]['label'],
        'depth_description': DEPTHS[depth]['description'],
        'profile': profile,
        'chunks': chunks,
        'pack_tokens': pack_tokens,
        'model': model,
        'model_context': model_context(model),
        'usable_input_tokens': usable,
        'suggested_model': suggested_model,
        'suggest_model': bool(needs_bigger_model),
        'rationale': rationale,
        'severity_hint': _verdict_hint(severity),
    }


def suggest_model(pack_tokens, preferred='openai/gpt-4o-mini'):
    """Pick a model with enough context for this pack."""
    if model_context(preferred) * SAFETY_MARGIN >= pack_tokens:
        return preferred
    for candidate in ('openai/gpt-4o', 'openai/gpt-4.1', 'anthropic/claude-3.5-sonnet'):
        if model_context(candidate) * SAFETY_MARGIN >= pack_tokens:
            return candidate
    return preferred
