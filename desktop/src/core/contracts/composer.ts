export interface ComposerDraft {
  target: string;
  prompt: string;
  instruction: string;
  limitsOpen: boolean;
  minutes: string;
  tokens: string;
}

export const EMPTY_COMPOSER_DRAFT: ComposerDraft = {
  target: "", prompt: "", instruction: "", minutes: "", tokens: "", limitsOpen: false,
};
