const spanishTypes = [
    { type: 'feat', section: 'Nuevas funcionalidades' },
    { type: 'fix', section: 'Correcciones' },
    { type: 'perf', section: 'Rendimiento' },
    { type: 'revert', section: 'Reversiones' },
    { type: 'docs', section: 'Documentación', hidden: true },
    { type: 'test', section: 'Pruebas', hidden: true },
    { type: 'build', section: 'Compilación', hidden: true },
    { type: 'ci', section: 'Integración continua', hidden: true },
    { type: 'chore', section: 'Mantenimiento', hidden: true },
    { type: 'refactor', section: 'Refactorización', hidden: true },
]

export default {
    branches: ['main'],
    tagFormat: 'v${version}',
    plugins: [
        ['@semantic-release/commit-analyzer', {
            preset: 'conventionalcommits', presetConfig: { types: spanishTypes },
        }],
        ['@semantic-release/release-notes-generator', {
            preset: 'conventionalcommits', presetConfig: { types: spanishTypes },
        }],
        ['@semantic-release/changelog', { changelogFile: 'CHANGELOG.md' }],
        '@semantic-release/npm',
        ['@semantic-release/github', { successComment: false, failComment: false }],
        ['@semantic-release/git', {
            assets: ['CHANGELOG.md', 'package.json', 'package-lock.json'],
            message: 'chore(release): ${nextRelease.version} [skip ci]\n\n${nextRelease.notes}',
        }],
    ],
}
