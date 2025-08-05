package hash

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/DavidHospinal/CryptoToolkit-Go/pkg/crypto/common"
)

type MerkleNode struct {
	Hash   []byte
	Left   *MerkleNode
	Right  *MerkleNode
	Data   []byte // Solo para nodos hoja
	IsLeaf bool
}

type MerkleTree struct {
	Root        *MerkleNode
	Leaves      []*MerkleNode
	LeafCount   int
	TreeHeight  int
	ExplainMode bool
}

type MerkleProof struct {
	LeafHash    []byte
	LeafIndex   int
	ProofHashes [][]byte
	Directions  []bool // true = right, false = left
}

type MerkleExplanationStep struct {
	Step        int
	Description string
	Operation   string
	Details     string
}

// NewMerkleTree crea un nuevo árbol de Merkle
func NewMerkleTree(explainMode bool) *MerkleTree {
	return &MerkleTree{
		ExplainMode: explainMode,
		Leaves:      make([]*MerkleNode, 0),
	}
}

// BuildFromData construye un árbol de Merkle desde datos
func (mt *MerkleTree) BuildFromData(data []string) ([]MerkleExplanationStep, error) {
	var steps []MerkleExplanationStep

	if len(data) < 2 {
		return nil, common.ErrMerkleTreeTooSmall
	}

	if mt.ExplainMode {
		steps = append(steps, MerkleExplanationStep{
			Step:        1,
			Description: "Validación de datos",
			Operation:   fmt.Sprintf("Verificando %d elementos de entrada", len(data)),
			Details:     "Se requieren al menos 2 elementos para construir un árbol de Merkle",
		})
	}

	// Crear nodos hoja
	mt.Leaves = make([]*MerkleNode, len(data))
	for i, item := range data {
		hash := sha256.Sum256([]byte(item))
		mt.Leaves[i] = &MerkleNode{
			Hash:   hash[:],
			Data:   []byte(item),
			IsLeaf: true,
		}
	}

	mt.LeafCount = len(data)

	if mt.ExplainMode {
		steps = append(steps, MerkleExplanationStep{
			Step:        2,
			Description: "Creación de hojas",
			Operation:   fmt.Sprintf("Generados %d nodos hoja con hash SHA-256", len(data)),
			Details:     "Cada hoja contiene hash(datos) usando SHA-256",
		})
	}

	// Construir el árbol
	currentLevel := make([]*MerkleNode, len(mt.Leaves))
	copy(currentLevel, mt.Leaves)
	level := 1

	for len(currentLevel) > 1 {
		nextLevel := make([]*MerkleNode, 0)

		// Emparejar nodos del nivel actual
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right *MerkleNode

			// Si hay número impar de nodos, duplicar el último
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = currentLevel[i] // Duplicar el último nodo
			}

			// Crear nodo padre
			parent := mt.createParentNode(left, right)
			nextLevel = append(nextLevel, parent)
		}

		if mt.ExplainMode {
			steps = append(steps, MerkleExplanationStep{
				Step:        2 + level,
				Description: fmt.Sprintf("Nivel %d del árbol", level),
				Operation:   fmt.Sprintf("Combinados %d nodos en %d nodos padre", len(currentLevel), len(nextLevel)),
				Details:     "Cada nodo padre = hash(hijo_izquierdo + hijo_derecho)",
			})
		}

		currentLevel = nextLevel
		level++
	}

	// El último nodo es la raíz
	mt.Root = currentLevel[0]
	mt.TreeHeight = level - 1

	if mt.ExplainMode {
		steps = append(steps, MerkleExplanationStep{
			Step:        2 + level,
			Description: "Árbol completado",
			Operation:   fmt.Sprintf("Raíz de Merkle calculada con altura %d", mt.TreeHeight),
			Details:     fmt.Sprintf("Hash raíz: %x", mt.Root.Hash),
		})
	}

	return steps, nil
}

// createParentNode crea un nodo padre desde dos nodos hijos
func (mt *MerkleTree) createParentNode(left, right *MerkleNode) *MerkleNode {
	// Concatenar hashes de los hijos
	combined := append(left.Hash, right.Hash...)

	// Calcular hash del nodo padre
	hash := sha256.Sum256(combined)

	return &MerkleNode{
		Hash:   hash[:],
		Left:   left,
		Right:  right,
		IsLeaf: false,
	}
}

// GetRoot retorna el hash de la raíz
func (mt *MerkleTree) GetRoot() []byte {
	if mt.Root == nil {
		return nil
	}
	return mt.Root.Hash
}

// GetRootHex retorna el hash de la raíz en hexadecimal
func (mt *MerkleTree) GetRootHex() string {
	root := mt.GetRoot()
	if root == nil {
		return ""
	}
	return fmt.Sprintf("%x", root)
}

// GenerateProof genera una prueba de Merkle para un elemento específico
func (mt *MerkleTree) GenerateProof(dataIndex int) (*MerkleProof, error) {
	if dataIndex < 0 || dataIndex >= len(mt.Leaves) {
		return nil, fmt.Errorf("invalid data index: %d", dataIndex)
	}

	proof := &MerkleProof{
		LeafHash:    mt.Leaves[dataIndex].Hash,
		LeafIndex:   dataIndex,
		ProofHashes: make([][]byte, 0),
		Directions:  make([]bool, 0),
	}

	// Recorrer desde la hoja hasta la raíz
	currentIndex := dataIndex

	// Reconstruir el camino hacia la raíz
	levelSize := len(mt.Leaves)

	for levelSize > 1 {
		// Determinar si estamos en posición par o impar
		if currentIndex%2 == 0 {
			// Posición par - necesitamos el hermano derecho
			if currentIndex+1 < levelSize {
				// Hay hermano derecho
				siblingIndex := currentIndex + 1
				siblingHash := mt.getSiblingHashAtLevel(dataIndex, siblingIndex)
				proof.ProofHashes = append(proof.ProofHashes, siblingHash)
				proof.Directions = append(proof.Directions, true) // hermano a la derecha
			}
		} else {
			// Posición impar - necesitamos el hermano izquierdo
			siblingIndex := currentIndex - 1
			siblingHash := mt.getSiblingHashAtLevel(dataIndex, siblingIndex)
			proof.ProofHashes = append(proof.ProofHashes, siblingHash)
			proof.Directions = append(proof.Directions, false) // hermano a la izquierda
		}

		// Subir al siguiente nivel
		currentIndex = currentIndex / 2
		levelSize = (levelSize + 1) / 2
	}

	return proof, nil
}

// getSiblingHashAtLevel obtiene el hash del hermano en un nivel específico
func (mt *MerkleTree) getSiblingHashAtLevel(originalIndex, siblingIndex int) []byte {
	if siblingIndex < len(mt.Leaves) {
		return mt.Leaves[siblingIndex].Hash
	}
	// Si no hay hermano, usar el mismo nodo (duplicación)
	return mt.Leaves[originalIndex].Hash
}

// VerifyProof verifica una prueba de Merkle
func (mt *MerkleTree) VerifyProof(data string, proof *MerkleProof) (bool, []MerkleExplanationStep, error) {
	var steps []MerkleExplanationStep

	if mt.Root == nil {
		return false, steps, fmt.Errorf("merkle tree not built")
	}

	// Calcular hash de los datos
	dataHash := sha256.Sum256([]byte(data))

	if mt.ExplainMode {
		steps = append(steps, MerkleExplanationStep{
			Step:        1,
			Description: "Validación inicial",
			Operation:   fmt.Sprintf("Hash de datos: %x", dataHash),
			Details:     "Comparando con hash de hoja en la prueba",
		})
	}

	// Verificar que el hash de los datos coincide con el hash de la hoja
	if !common.SecureCompare(dataHash[:], proof.LeafHash) {
		return false, steps, nil
	}

	// Reconstruir el camino hacia la raíz usando la prueba
	currentHash := proof.LeafHash

	for i, siblingHash := range proof.ProofHashes {
		direction := proof.Directions[i]

		var combined []byte
		if direction {
			// Hermano a la derecha
			combined = append(currentHash, siblingHash...)
		} else {
			// Hermano a la izquierda
			combined = append(siblingHash, currentHash...)
		}

		// Calcular hash del nodo padre
		parentHash := sha256.Sum256(combined)
		currentHash = parentHash[:]

		if mt.ExplainMode {
			steps = append(steps, MerkleExplanationStep{
				Step:        2 + i,
				Description: fmt.Sprintf("Verificación nivel %d", i+1),
				Operation:   fmt.Sprintf("Hash padre: %x", currentHash),
				Details:     fmt.Sprintf("Combinando con hermano: %x", siblingHash),
			})
		}
	}

	// Comparar con la raíz del árbol
	isValid := common.SecureCompare(currentHash, mt.Root.Hash)

	if mt.ExplainMode {
		steps = append(steps, MerkleExplanationStep{
			Step:        len(proof.ProofHashes) + 2,
			Description: "Resultado final",
			Operation:   fmt.Sprintf("Verificación: %s", map[bool]string{true: "VÁLIDA", false: "INVÁLIDA"}[isValid]),
			Details:     fmt.Sprintf("Hash calculado vs raíz: %s", map[bool]string{true: "COINCIDEN", false: "NO COINCIDEN"}[isValid]),
		})
	}

	return isValid, steps, nil
}

// VisualizeTree genera una representación visual del árbol
func (mt *MerkleTree) VisualizeTree() string {
	if mt.Root == nil {
		return "Árbol vacío"
	}

	var result strings.Builder
	result.WriteString("ÁRBOL DE MERKLE:\n\n")

	// Generar visualización nivel por nivel
	levels := mt.getLevels()

	for levelIndex, level := range levels {
		// Agregar espaciado según el nivel
		indent := strings.Repeat("  ", mt.TreeHeight-levelIndex)

		result.WriteString(fmt.Sprintf("Nivel %d:%s", levelIndex, indent))

		for i, node := range level {
			hashStr := fmt.Sprintf("%x", node.Hash)
			shortHash := hashStr[:8] // Mostrar solo los primeros 8 caracteres

			if node.IsLeaf {
				result.WriteString(fmt.Sprintf("[%s*]", shortHash))
			} else {
				result.WriteString(fmt.Sprintf("[%s]", shortHash))
			}

			if i < len(level)-1 {
				result.WriteString("  ")
			}
		}
		result.WriteString("\n")
	}

	result.WriteString("\n* = Nodo hoja")
	result.WriteString(fmt.Sprintf("\nRaíz completa: %x", mt.Root.Hash))
	result.WriteString(fmt.Sprintf("\nAltura: %d niveles", mt.TreeHeight))
	result.WriteString(fmt.Sprintf("\nHojas: %d elementos", mt.LeafCount))

	return result.String()
}

// getLevels obtiene todos los nodos organizados por niveles
func (mt *MerkleTree) getLevels() [][]*MerkleNode {
	if mt.Root == nil {
		return nil
	}

	levels := make([][]*MerkleNode, 0)

	// Comenzar con las hojas (nivel más bajo)
	levels = append(levels, mt.Leaves)

	// Construir niveles superiores
	currentLevel := mt.Leaves

	for len(currentLevel) > 1 {
		nextLevel := make([]*MerkleNode, 0)

		// Encontrar padres de nodos del nivel actual
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right *MerkleNode

			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				right = left // Duplicar si es impar
			}

			// Buscar el nodo padre que tenga estos hijos
			parent := mt.findParent(left, right)
			if parent != nil && !mt.containsNode(nextLevel, parent) {
				nextLevel = append(nextLevel, parent)
			}
		}

		if len(nextLevel) > 0 {
			levels = append(levels, nextLevel)
			currentLevel = nextLevel
		} else {
			break
		}
	}

	return levels
}

// findParent busca el nodo padre que tiene los hijos especificados
func (mt *MerkleTree) findParent(left, right *MerkleNode) *MerkleNode {
	return mt.searchParent(mt.Root, left, right)
}

// searchParent busca recursivamente el padre
func (mt *MerkleTree) searchParent(node, left, right *MerkleNode) *MerkleNode {
	if node == nil || node.IsLeaf {
		return nil
	}

	// Verificar si este nodo es el padre buscado
	if node.Left == left && node.Right == right {
		return node
	}

	// Buscar en subárboles
	if result := mt.searchParent(node.Left, left, right); result != nil {
		return result
	}

	return mt.searchParent(node.Right, left, right)
}

// containsNode verifica si un slice contiene un nodo específico
func (mt *MerkleTree) containsNode(nodes []*MerkleNode, target *MerkleNode) bool {
	for _, node := range nodes {
		if node == target {
			return true
		}
	}
	return false
}

// FormatProofForAPI formatea una prueba para la respuesta de API
func (proof *MerkleProof) FormatProofForAPI() string {
	if len(proof.ProofHashes) == 0 {
		return ""
	}

	parts := make([]string, len(proof.ProofHashes))
	for i, hash := range proof.ProofHashes {
		parts[i] = fmt.Sprintf("%x", hash)
	}

	return strings.Join(parts, ",")
}
