// Критерії оцінювання
const criteria = [
	{ id: 'K1', name: 'K₁ - Ризики втрати контролю в польоті' },
	{ id: 'K2', name: 'K₂ - Ризики невиконання функції відлякування' },
	{ id: 'K3', name: "K₃ - Ризики зіткнення з об'єктами" },
	{ id: 'K4', name: 'K₄ - Ризики хакерських атак' },
	{ id: 'K5', name: 'K₅ - Ризики погіршення метеоумов' },
	{ id: 'K6', name: 'K₆ - Ризики екстреної посадки' },
	{ id: 'K7', name: 'K₇ - Ризики втрати сигналу з диспетчером' },
]

// Лінгвістичні терми
const terms = [
	{ value: 'T1', label: 'T₁ - Мінімальна можливість', range: [0, 20] },
	{ value: 'T2', label: 'T₂ - Нижче середнього', range: [20, 40] },
	{ value: 'T3', label: 'T₃ - Середня можливість', range: [40, 60] },
	{ value: 'T4', label: 'T₄ - Висока можливість', range: [60, 80] },
	{ value: 'T5', label: 'T₅ - Критична можливість', range: [80, 100] },
]

/**
 * Ініціалізація інтерфейсу
 */
function initInterface() {
	const tbody = document.getElementById('criteriaBody')
	criteria.forEach((criterion, index) => {
		const row = document.createElement('tr')
		row.innerHTML = `
            <td>${criterion.name}</td>
            <td>
                <select id="${criterion.id}_term">
                    ${terms
											.map(
												t => `<option value="${t.value}">${t.label}</option>`
											)
											.join('')}
                </select>
            </td>
            <td>
                <input type="number" id="${
									criterion.id
								}_conf" min="0" max="1" step="0.1" value="0.5">
            </td>
            <td>
                <input type="number" id="${
									criterion.id
								}_weight" min="1" max="10" value="${5 + (index % 3)}">
            </td>
        `
		tbody.appendChild(row)
	})
}

/**
 * Фазифікація вхідних знань (Крок 1)
 * Перетворення лінгвістичних оцінок у числові значення
 * @param {string} term - Лінгвістичний терм (T1-T5)
 * @param {number} conf - Достовірність експерта (0-1)
 * @returns {number} - Фазифіковане значення (0-1)
 */
function fuzzify(term, conf) {
	const ranges = {
		T1: [0, 20],
		T2: [20, 40],
		T3: [40, 60],
		T4: [60, 80],
		T5: [80, 100],
	}
	const [a, b] = ranges[term]

	// Квадратичний S-сплайн
	if (conf <= 0.5) {
		return (1 / 100) * (Math.pow(conf / 0.5, 2) * (b - a) + a)
	} else {
		return (1 / 100) * (b - Math.pow((1 - conf) / 0.5, 2) * (b - a))
	}
}

/**
 * Нормування вагових коефіцієнтів (Крок 2)
 * @param {number[]} weights - Масив ваг критеріїв
 * @returns {number[]} - Нормовані ваги (сума = 1)
 */
function normalize(weights) {
	const sum = weights.reduce((a, b) => a + b, 0)
	return weights.map(w => w / sum)
}

/**
 * Агрегування за сценарієм (Крок 3)
 * @param {string} scenario - Обраний сценарій (S1-S4)
 * @param {number[]} deltas - Фазифіковані значення критеріїв
 * @param {number[]} omega - Нормовані ваги
 * @returns {number} - Агрегована оцінка S(P)
 */
function aggregate(scenario, deltas, omega) {
	switch (scenario) {
		case 'S1': // Песимістичний (гармонічне середнє)
			return 1 / deltas.reduce((sum, d, i) => sum + omega[i] / (1 - d), 0)

		case 'S2': // Обережний (геометричне середнє)
			return deltas.reduce((prod, d, i) => prod * Math.pow(1 - d, omega[i]), 1)

		case 'S3': // Середній (арифметичне середнє)
			return deltas.reduce((sum, d, i) => sum + omega[i] * (1 - d), 0)

		case 'S4': // Оптимістичний (квадратичне середнє)
			return Math.sqrt(
				deltas.reduce((sum, d, i) => sum + omega[i] * Math.pow(1 - d, 2), 0)
			)

		default:
			return 0
	}
}

/**
 * Врахування рівня загроз (Крок 4)
 * @param {number} SP - Агрегована оцінка S(P)
 * @param {string} threat - Рівень загроз (C1-C5)
 * @returns {number} - Фінальна оцінка r(P)
 */
function threatAdjust(SP, threat) {
	const deltaValues = {
		C1: 8 / 9, // Мінімальний
		C2: 7 / 9, // Низький
		C3: 5 / 9, // Середній
		C4: 3 / 9, // Високий
		C5: 1 / 9, // Максимальний
	}
	const delta = deltaValues[threat]

	// Обмеження значення в діапазоні [0, 1]
	const bounded = Math.min(Math.max(SP, 0), 1)
	return Math.pow(bounded, delta)
}

/**
 * Дефазифікація та прийняття рішень (Крок 5)
 * @param {number} r - Фінальна оцінка r(P)
 * @returns {string} - Лінгвістичний висновок
 */
function defuzzify(r) {
	if (r > 0.8) return 'R₁(P) — Високий рівень безпеки ✅'
	if (r > 0.6) return 'R₂(P) — Вище середнього ✓'
	if (r > 0.4) return 'R₃(P) — Середній ⚠️'
	if (r > 0.2) return 'R₄(P) — Низький ⚠️'
	return 'R₅(P) — Дуже низький ❌'
}

/**
 * Головна функція розрахунку ризику
 */
function calculateRisk() {
	const deltas = []
	const weights = []

	// Збір вхідних даних
	criteria.forEach(c => {
		const term = document.getElementById(`${c.id}_term`).value
		const conf = parseFloat(document.getElementById(`${c.id}_conf`).value)
		const weight = parseFloat(document.getElementById(`${c.id}_weight`).value)

		deltas.push(fuzzify(term, conf))
		weights.push(weight)
	})

	// Обчислення
	const omega = normalize(weights)
	const scenario = document.getElementById('scenario').value
	const SP = aggregate(scenario, deltas, omega)
	const threatLevel = document.getElementById('threatLevel').value
	const rP = threatAdjust(SP, threatLevel)

	// Відображення результатів
	document.getElementById('riskValue').textContent = rP.toFixed(3)
	document.getElementById('gaugeFill').style.strokeDashoffset =
		251.2 - rP * 251.2
	document.getElementById('conclusion').textContent = defuzzify(rP)
	document.getElementById('results').classList.add('show')

	// Побудова діаграми впливу критеріїв
	const chart = document.getElementById('barChart')
	chart.innerHTML = ''
	criteria.forEach((c, i) => {
		const contribution = omega[i] * (1 - deltas[i])
		const bar = document.createElement('div')
		bar.className = 'bar-item'
		bar.innerHTML = `
            <div class="bar-label">${c.id}</div>
            <div class="bar-container">
                <div class="bar-fill" style="width:${contribution * 100}%">
                    <span>${(contribution * 100).toFixed(1)}%</span>
                </div>
            </div>
        `
		chart.appendChild(bar)
	})
}

// Ініціалізація при завантаженні сторінки
window.onload = initInterface
