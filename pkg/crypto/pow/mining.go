package pow

import (
	"crypto/sha256"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/common"
)

type Block struct {
	Index        int       `json:"index"`
	Timestamp    time.Time `json:"timestamp"`
	Data         string    `json:"data"`
	PreviousHash string    `json:"previousHash"`
	Hash         string    `json:"hash"`
	Nonce        int       `json:"nonce"`
	Difficulty   int       `json:"difficulty"`
	Target       string    `json:"target"`
}

type MiningResult struct {
	Success  bool                    `json:"success"`
	Block    *Block                  `json:"block"`
	Attempts int                     `json:"attempts"`
	Duration time.Duration           `json:"duration"`
	HashRate float64                 `json:"hashRate"` // Hashes per second
	Steps    []MiningExplanationStep `json:"steps,omitempty"`
}

type MiningExplanationStep struct {
	Step        int    `json:"step"`
	Description string `json:"description"`
	Operation   string `json:"operation"`
	Details     string `json:"details"`
}

type DifficultyAdjustment struct {
	CurrentDifficulty int     `json:"currentDifficulty"`
	NewDifficulty     int     `json:"newDifficulty"`
	AdjustmentFactor  float64 `json:"adjustmentFactor"`
	TargetTime        int     `json:"targetTime"`
	ActualTime        int     `json:"actualTime"`
	Recommendation    string  `json:"recommendation"`
}

type Miner struct {
	ExplainMode bool
	MaxAttempts int
}

// NewMiner crea una nueva instancia de minero
func NewMiner(explainMode bool) *Miner {
	return &Miner{
		ExplainMode: explainMode,
		MaxAttempts: common.POWMaxAttempts,
	}
}

// NewBlock crea un nuevo bloque
func NewBlock(index int, data string, previousHash string, difficulty int) *Block {
	return &Block{
		Index:        index,
		Timestamp:    time.Now(),
		Data:         data,
		PreviousHash: previousHash,
		Difficulty:   difficulty,
		Target:       generateTarget(difficulty),
		Nonce:        0,
	}
}

// MineBlock realiza el minado de un bloque con Proof of Work
func (m *Miner) MineBlock(block *Block) (*MiningResult, error) {
	var steps []MiningExplanationStep

	if err := common.ValidatePOWDifficulty(block.Difficulty); err != nil {
		return nil, err
	}

	if m.ExplainMode {
		steps = append(steps, MiningExplanationStep{
			Step:        1,
			Description: "Inicialización del minado",
			Operation:   fmt.Sprintf("Objetivo: hash con %d ceros iniciales", block.Difficulty),
			Details:     fmt.Sprintf("Target: %s", block.Target),
		})
	}

	startTime := time.Now()
	attempts := 0
	target := generateTarget(block.Difficulty)

	if m.ExplainMode {
		steps = append(steps, MiningExplanationStep{
			Step:        2,
			Description: "Preparación de datos",
			Operation:   "Combinar: índice + timestamp + datos + hash_anterior + nonce",
			Details:     fmt.Sprintf("Datos base: %s", block.getBaseString()),
		})
	}

	// Bucle principal de minado
	for attempts < m.MaxAttempts {
		block.Nonce = attempts

		// Crear string del bloque
		blockString := block.getBlockString()

		// Calcular hash
		hash := sha256.Sum256([]byte(blockString))
		hashHex := fmt.Sprintf("%x", hash)

		// Verificar si cumple el objetivo
		if m.isValidHash(hashHex, target) {
			block.Hash = hashHex
			duration := time.Since(startTime)
			hashRate := float64(attempts+1) / duration.Seconds()

			if m.ExplainMode {
				steps = append(steps, MiningExplanationStep{
					Step:        3,
					Description: "¡Nonce válido encontrado!",
					Operation:   fmt.Sprintf("Hash válido: %s", hashHex),
					Details:     fmt.Sprintf("Nonce ganador: %d después de %d intentos", block.Nonce, attempts+1),
				})
			}

			return &MiningResult{
				Success:  true,
				Block:    block,
				Attempts: attempts + 1,
				Duration: duration,
				HashRate: hashRate,
				Steps:    steps,
			}, nil
		}

		attempts++

		// Log de progreso cada cierta cantidad de intentos
		if m.ExplainMode && attempts%1000 == 0 {
			steps = append(steps, MiningExplanationStep{
				Step:        2 + attempts/1000,
				Description: fmt.Sprintf("Progreso: %d intentos", attempts),
				Operation:   fmt.Sprintf("Último hash: %s", hashHex[:16]+"..."),
				Details:     fmt.Sprintf("Tasa actual: %.0f H/s", float64(attempts)/time.Since(startTime).Seconds()),
			})
		}
	}

	// Límite de intentos alcanzado
	duration := time.Since(startTime)
	hashRate := float64(attempts) / duration.Seconds()

	return &MiningResult{
		Success:  false,
		Block:    block,
		Attempts: attempts,
		Duration: duration,
		HashRate: hashRate,
		Steps:    steps,
	}, common.ErrPOWMaxAttemptsReached
}

// generateTarget genera la cadena objetivo para la dificultad dada
func generateTarget(difficulty int) string {
	if difficulty <= 0 {
		return ""
	}
	return strings.Repeat("0", difficulty)
}

// isValidHash verifica si un hash cumple con el objetivo
func (m *Miner) isValidHash(hash, target string) bool {
	if len(target) > len(hash) {
		return false
	}
	return strings.HasPrefix(hash, target)
}

// getBaseString retorna la string base del bloque sin nonce
func (b *Block) getBaseString() string {
	return fmt.Sprintf("%d%s%s%s",
		b.Index,
		b.Timestamp.Format(time.RFC3339),
		b.Data,
		b.PreviousHash)
}

// getBlockString retorna la string completa del bloque incluyendo nonce
func (b *Block) getBlockString() string {
	return fmt.Sprintf("%s%d", b.getBaseString(), b.Nonce)
}

// CalculateExpectedAttempts estima el número de intentos necesarios
func CalculateExpectedAttempts(difficulty int) int {
	if difficulty <= 0 {
		return 1
	}
	return int(math.Pow(16, float64(difficulty))) / 2
}

// AdjustDifficulty ajusta la dificultad basándose en el tiempo objetivo vs real
func AdjustDifficulty(currentDifficulty, targetTimeSeconds, actualTimeSeconds int) *DifficultyAdjustment {
	if targetTimeSeconds <= 0 || actualTimeSeconds <= 0 {
		return &DifficultyAdjustment{
			CurrentDifficulty: currentDifficulty,
			NewDifficulty:     currentDifficulty,
			AdjustmentFactor:  1.0,
			Recommendation:    "Tiempos inválidos - sin cambios",
		}
	}

	// Calcular factor de ajuste
	adjustmentFactor := float64(targetTimeSeconds) / float64(actualTimeSeconds)

	// Limitar ajustes extremos (como Bitcoin - factor máximo de 4)
	if adjustmentFactor > 4.0 {
		adjustmentFactor = 4.0
	} else if adjustmentFactor < 0.25 {
		adjustmentFactor = 0.25
	}

	// Calcular nueva dificultad
	newDifficulty := currentDifficulty
	var recommendation string

	if adjustmentFactor > 1.1 {
		// Bloques muy lentos - aumentar dificultad
		newDifficulty = common.Min(currentDifficulty+1, common.POWMaxDifficulty)
		recommendation = "Minado muy lento - incrementar dificultad"
	} else if adjustmentFactor < 0.9 {
		// Bloques muy rápidos - disminuir dificultad
		newDifficulty = common.Max(currentDifficulty-1, common.POWMinDifficulty)
		recommendation = "Minado muy rápido - decrementar dificultad"
	} else {
		// Dentro del rango aceptable
		recommendation = "Dificultad apropiada - sin cambios necesarios"
	}

	return &DifficultyAdjustment{
		CurrentDifficulty: currentDifficulty,
		NewDifficulty:     newDifficulty,
		AdjustmentFactor:  adjustmentFactor,
		TargetTime:        targetTimeSeconds,
		ActualTime:        actualTimeSeconds,
		Recommendation:    recommendation,
	}
}

// ValidateBlock verifica que un bloque tenga un hash válido
func ValidateBlock(block *Block) bool {
	if block == nil {
		return false
	}

	// Verificar que el hash almacenado coincide con el calculado
	blockString := block.getBlockString()
	hash := sha256.Sum256([]byte(blockString))
	calculatedHash := fmt.Sprintf("%x", hash)

	if block.Hash != calculatedHash {
		return false
	}

	// Verificar que cumple con la dificultad
	target := generateTarget(block.Difficulty)
	return strings.HasPrefix(block.Hash, target)
}

// MineBlockInteractive realiza minado con callback de progreso
func (b *Block) MineBlockInteractive(difficulty int, progressCallback func(attempts int, hashRate float64)) (*MiningResult, error) {
	miner := NewMiner(false) // Sin explicaciones para mejor rendimiento
	miner.MaxAttempts = common.POWMaxAttempts

	b.Difficulty = difficulty
	b.Target = generateTarget(difficulty)

	startTime := time.Now()
	attempts := 0
	target := generateTarget(difficulty)

	for attempts < miner.MaxAttempts {
		b.Nonce = attempts

		// Calcular hash
		blockString := b.getBlockString()
		hash := sha256.Sum256([]byte(blockString))
		hashHex := fmt.Sprintf("%x", hash)

		// Verificar si es válido
		if strings.HasPrefix(hashHex, target) {
			b.Hash = hashHex
			duration := time.Since(startTime)
			hashRate := float64(attempts+1) / duration.Seconds()

			return &MiningResult{
				Success:  true,
				Block:    b,
				Attempts: attempts + 1,
				Duration: duration,
				HashRate: hashRate,
			}, nil
		}

		attempts++

		// Callback de progreso cada 1000 intentos
		if progressCallback != nil && attempts%1000 == 0 {
			hashRate := float64(attempts) / time.Since(startTime).Seconds()
			progressCallback(attempts, hashRate)
		}
	}

	return &MiningResult{
		Success:  false,
		Block:    b,
		Attempts: attempts,
		Duration: time.Since(startTime),
		HashRate: float64(attempts) / time.Since(startTime).Seconds(),
	}, common.ErrPOWMaxAttemptsReached
}

// AnalyzeDifficulty proporciona análisis detallado de dificultad
func (b *Block) AnalyzeDifficulty() map[string]interface{} {
	analysis := make(map[string]interface{})

	// Calcular métricas esperadas
	expectedAttempts := CalculateExpectedAttempts(b.Difficulty)
	expectedTimeSeconds := float64(expectedAttempts) / 1000.0 // Asumiendo 1000 H/s

	analysis["difficulty"] = b.Difficulty
	analysis["target"] = b.Target
	analysis["expectedAttempts"] = expectedAttempts
	analysis["expectedTimeSeconds"] = expectedTimeSeconds
	analysis["searchSpace"] = math.Pow(16, float64(b.Difficulty))
	analysis["probability"] = 1.0 / math.Pow(16, float64(b.Difficulty))

	// Análisis de seguridad
	if b.Difficulty >= 6 {
		analysis["securityLevel"] = "Alta"
	} else if b.Difficulty >= 4 {
		analysis["securityLevel"] = "Media"
	} else {
		analysis["securityLevel"] = "Baja"
	}

	return analysis
}

// CompareAlgorithms compara diferentes enfoques de minado
func (b *Block) CompareAlgorithms() map[string]interface{} {
	comparison := make(map[string]interface{})

	// Simulación de diferentes algoritmos
	sha256Info := map[string]interface{}{
		"algorithm":   "SHA-256",
		"hashSize":    "256 bits",
		"security":    "Excelente",
		"speed":       "Rápido",
		"energyUsage": "Alto",
		"quantum":     "Vulnerable",
		"description": "Algoritmo usado por Bitcoin",
	}

	scryptInfo := map[string]interface{}{
		"algorithm":   "Scrypt",
		"hashSize":    "256 bits",
		"security":    "Excelente",
		"speed":       "Medio",
		"energyUsage": "Medio",
		"quantum":     "Vulnerable",
		"description": "Algoritmo usado por Litecoin",
	}

	comparison["sha256"] = sha256Info
	comparison["scrypt"] = scryptInfo

	return comparison
}

// EnergyCalculation estima el consumo energético del minado
func (b *Block) EnergyCalculation() map[string]interface{} {
	calculation := make(map[string]interface{})

	// Estimaciones basadas en hardware típico
	expectedAttempts := CalculateExpectedAttempts(b.Difficulty)

	// Estimaciones por tipo de hardware
	cpuHashRate := 1000.0       // H/s
	gpuHashRate := 50000.0      // H/s
	asicHashRate := 100000000.0 // H/s (100 MH/s)

	cpuPower := 100.0   // Watts
	gpuPower := 300.0   // Watts
	asicPower := 1500.0 // Watts

	// Calcular tiempo y energía para cada tipo
	cpuTime := float64(expectedAttempts) / cpuHashRate
	gpuTime := float64(expectedAttempts) / gpuHashRate
	asicTime := float64(expectedAttempts) / asicHashRate

	cpuEnergy := (cpuTime * cpuPower) / 3600.0    // Wh
	gpuEnergy := (gpuTime * gpuPower) / 3600.0    // Wh
	asicEnergy := (asicTime * asicPower) / 3600.0 // Wh

	calculation["estimatedAttempts"] = expectedAttempts
	calculation["cpu"] = map[string]interface{}{
		"hashRate":    cpuHashRate,
		"timeSeconds": cpuTime,
		"powerWatts":  cpuPower,
		"energyWh":    cpuEnergy,
		"cost$":       cpuEnergy * 0.12, // $0.12/kWh
	}
	calculation["gpu"] = map[string]interface{}{
		"hashRate":    gpuHashRate,
		"timeSeconds": gpuTime,
		"powerWatts":  gpuPower,
		"energyWh":    gpuEnergy,
		"cost$":       gpuEnergy * 0.12,
	}
	calculation["asic"] = map[string]interface{}{
		"hashRate":    asicHashRate,
		"timeSeconds": asicTime,
		"powerWatts":  asicPower,
		"energyWh":    asicEnergy,
		"cost$":       asicEnergy * 0.12,
	}

	return calculation
}

// GetMiningStatistics retorna estadísticas completas de minado
func GetMiningStatistics(blocks []*Block) map[string]interface{} {
	if len(blocks) == 0 {
		return map[string]interface{}{"error": "No blocks provided"}
	}

	stats := make(map[string]interface{})

	totalAttempts := 0
	difficulties := make([]int, len(blocks))

	for i, block := range blocks {
		// Estimar intentos basado en nonce
		totalAttempts += block.Nonce + 1
		difficulties[i] = block.Difficulty
	}

	// Calcular promedios
	avgAttempts := float64(totalAttempts) / float64(len(blocks))
	avgDifficulty := 0
	for _, diff := range difficulties {
		avgDifficulty += diff
	}
	avgDifficulty = avgDifficulty / len(blocks)

	stats["totalBlocks"] = len(blocks)
	stats["totalAttempts"] = totalAttempts
	stats["averageAttempts"] = avgAttempts
	stats["averageDifficulty"] = avgDifficulty
	stats["difficulties"] = difficulties

	return stats
}

// SimulateDifficultyAdjustment simula ajustes de dificultad a lo largo del tiempo
func SimulateDifficultyAdjustment(initialDifficulty int, targetBlockTime int, periods int) []DifficultyAdjustment {
	adjustments := make([]DifficultyAdjustment, periods)
	currentDifficulty := initialDifficulty

	for i := 0; i < periods; i++ {
		// Simular tiempo real variable (±50% del objetivo)
		variance := 0.5
		factor := 1.0 + (variance * (2.0 * float64(i%3-1))) // -0.5, 0, +0.5 rotation
		simulatedTime := int(float64(targetBlockTime) * (1.0 + factor*0.3))

		adjustment := AdjustDifficulty(currentDifficulty, targetBlockTime, simulatedTime)
		adjustments[i] = *adjustment
		currentDifficulty = adjustment.NewDifficulty
	}

	return adjustments
}

// ValidateProofOfWork verifica que un bloque tenga prueba de trabajo válida
func ValidateProofOfWork(blockData, previousHash string, nonce, difficulty int) (bool, string) {
	// Recrear el bloque
	block := &Block{
		Data:         blockData,
		PreviousHash: previousHash,
		Nonce:        nonce,
		Difficulty:   difficulty,
	}

	// Calcular hash
	blockString := block.getBlockString()
	hash := sha256.Sum256([]byte(blockString))
	hashHex := fmt.Sprintf("%x", hash)

	// Verificar que cumple con la dificultad
	target := generateTarget(difficulty)
	isValid := strings.HasPrefix(hashHex, target)

	return isValid, hashHex
}

// AnalyzeNetworkSecurity analiza la seguridad de la red basada en dificultad
func AnalyzeNetworkSecurity(difficulty int, networkHashRate float64) map[string]interface{} {
	analysis := make(map[string]interface{})

	// Calcular métricas de seguridad
	expectedAttempts := float64(CalculateExpectedAttempts(difficulty))
	timeToBlock := expectedAttempts / networkHashRate

	// Costo de ataque del 51%
	halfNetworkHashRate := networkHashRate * 0.51
	costPer51Attack := halfNetworkHashRate * 0.12 * (timeToBlock / 3600.0) // $0.12/kWh

	// Nivel de seguridad
	var securityLevel string
	if difficulty >= 8 {
		securityLevel = "Extremadamente Seguro"
	} else if difficulty >= 6 {
		securityLevel = "Muy Seguro"
	} else if difficulty >= 4 {
		securityLevel = "Moderadamente Seguro"
	} else {
		securityLevel = "Baja Seguridad"
	}

	analysis["difficulty"] = difficulty
	analysis["networkHashRate"] = networkHashRate
	analysis["expectedBlockTime"] = timeToBlock
	analysis["securityLevel"] = securityLevel
	analysis["cost51Attack"] = costPer51Attack
	analysis["recommendedMinDifficulty"] = 4

	return analysis
}
